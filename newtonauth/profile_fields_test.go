package newtonauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Cookie crypto: AES-GCM round-trip + AAD binding + v1 rejection
// ---------------------------------------------------------------------------

func TestSessionCookieDoesNotCarryProfileFields(t *testing.T) {
	// Profile fields live in the cache, not the cookie. The cookie is only
	// a uid + platform_token bearer; profile is refreshed via auth-check on
	// every cache miss so consumers always see fresh data.
	value, err := buildSessionCookieValue("user-1", "tok", true, 3600, "secret", "client-A")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseSessionCookieValue(value, "secret", "client-A")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.UID != "user-1" || parsed.PlatformToken != "tok" {
		t.Fatalf("expected uid + platform_token to round-trip, got %+v", parsed)
	}
}

func TestSessionCookieUsesV2WireFormat(t *testing.T) {
	value, err := buildSessionCookieValue("user-1", "tok", true, 3600, "secret", "client-A")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value, "v2.") {
		t.Fatalf("expected v2. prefix, got %s", value[:8])
	}
	if got := strings.Count(value, "."); got != 2 {
		t.Fatalf("expected 3 dot-segments, got %d separators", got)
	}
}

func TestSessionCookieRejectsWrongClientID(t *testing.T) {
	value, err := buildSessionCookieValue("user-1", "tok", true, 3600, "secret", "client-A")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseSessionCookieValue(value, "secret", "client-B"); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession for AAD mismatch, got %v", err)
	}
}

func TestLegacyV1SignedCookieIsRejected(t *testing.T) {
	legacy, err := signValue(map[string]any{
		"uid":                 "user-1",
		"platform_token":      "tok",
		"authorized":          true,
		"session_ttl_seconds": 3600,
		"issued_at":           0,
		"nonce":               "abc",
	}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseSessionCookieValue(legacy, "secret", "client-A"); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected legacy v1 cookie to be rejected, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Callback path: profile fields → CallbackResult.User + session cookie + cache
// ---------------------------------------------------------------------------

func TestCallbackPopulatesUserProfileFields(t *testing.T) {
	auth := newTestAuth(t, newStubAPI(http.StatusOK, authCheckResponse{}))
	loginReq := httptest.NewRequest(http.MethodGet, "https://app.example.com/newton/login?next=/dashboard", nil)
	loginRR := httptest.NewRecorder()
	auth.LoginHandler().ServeHTTP(loginRR, loginReq)
	loginResp := loginRR.Result()
	stateCookie := mustCookie(t, loginResp, auth.config.StateCookieName)
	loginLocation, _ := url.Parse(loginResp.Header.Get("Location"))
	state := loginLocation.Query().Get("state")

	identity := buildTestCallbackAssertion(t, testCallbackSecret, testClientID, "https://api.example.com", callbackAssertion{
		Sub:                   "user-1",
		Aud:                   testClientID,
		Iss:                   "https://api.example.com",
		Authenticated:         true,
		Authorized:            true,
		ClientCacheTTLSeconds: 60,
		SessionTTLSeconds:     86400,
		PlatformToken:         "platform-token",
		FirstName:             "Ada",
		LastName:              "Lovelace",
		Email:                 "ada@example.com",
		Iat:                   time.Now().Unix(),
		Exp:                   time.Now().Add(time.Minute).Unix(),
	})
	callbackReq := httptest.NewRequest(http.MethodGet, "https://app.example.com/newton/callback?state="+url.QueryEscape(state)+"&identity="+url.QueryEscape(identity), nil)
	callbackReq.AddCookie(stateCookie)

	result, _, err := auth.HandleCallback(callbackReq)
	if err != nil {
		t.Fatal(err)
	}
	if result.User.FirstName != "Ada" || result.User.LastName != "Lovelace" || result.User.Email != "ada@example.com" {
		t.Fatalf("CallbackResult.User profile fields wrong: %+v", result.User)
	}

	cached, ok := auth.cache.get("user-1")
	if !ok {
		t.Fatal("expected callback to seed cache")
	}
	if cached.FirstName != "Ada" || cached.Email != "ada@example.com" {
		t.Fatalf("cache did not carry profile fields after callback: %+v", cached)
	}
}

// ---------------------------------------------------------------------------
// Authenticate: cache hit + auth-check refresh both expose profile fields
// ---------------------------------------------------------------------------

func TestAuthenticateCacheHitExposesProfileFields(t *testing.T) {
	auth := newTestAuth(t, newStubAPI(http.StatusOK, authCheckResponse{}))
	auth.cache.set("user-1", authCheckResponse{
		Authenticated:         true,
		Authorized:            true,
		UID:                   "user-1",
		FirstName:             "Ada",
		LastName:              "Lovelace",
		Email:                 "ada@example.com",
		ClientCacheTTLSeconds: 300,
	})
	cookie := buildValidSessionCookie(t, auth, "user-1", "tok", true, 86400)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	req.AddCookie(cookie)

	result, err := auth.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result.User == nil || result.User.FirstName != "Ada" || result.User.Email != "ada@example.com" {
		t.Fatalf("cache-hit user profile wrong: %+v", result.User)
	}
}

func TestAuthenticateRefreshPopulatesProfileFromAuthCheck(t *testing.T) {
	apiClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := authCheckResponse{
			Authenticated:         true,
			Authorized:            true,
			UID:                   "user-1",
			FirstName:             "Ada",
			LastName:              "Lovelace",
			Email:                 "ada@example.com",
			ClientCacheTTLSeconds: 60,
			SessionTTLSeconds:     86400,
		}
		rr := httptest.NewRecorder()
		rr.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(rr).Encode(body)
		return rr.Result(), nil
	})}
	auth := newTestAuth(t, apiClient)
	cookie := buildValidSessionCookie(t, auth, "user-1", "platform-token", true, 86400)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	req.AddCookie(cookie)

	result, err := auth.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result.User == nil || result.User.FirstName != "Ada" || result.User.Email != "ada@example.com" {
		t.Fatalf("refresh user profile wrong: %+v", result.User)
	}

	cached, ok := auth.cache.get("user-1")
	if !ok {
		t.Fatal("expected cache populated after refresh")
	}
	if cached.FirstName != "Ada" || cached.Email != "ada@example.com" {
		t.Fatalf("cache did not retain profile fields: %+v", cached)
	}
}
