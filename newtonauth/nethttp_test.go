package newtonauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testClientID       = "test-client"
	testClientSecret   = "test-secret"
	testCallbackSecret = "test-callback-secret"
	testNewtonAPIBase  = "https://api.example.com"
)

func TestLoginSetsStateCookieAndRedirectsToNewton(t *testing.T) {
	auth := newTestAuth(t, newStubAPI(http.StatusOK, authCheckResponse{}))
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/newton/login?next=/dashboard", nil)
	rr := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(rr, req)

	resp := rr.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	stateCookie := mustCookie(t, resp, auth.config.StateCookieName)
	if stateCookie.Value == "" {
		t.Fatal("expected state cookie")
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/platform-auth/login") {
		t.Fatalf("expected platform login redirect, got %s", location)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("client_id") != testClientID {
		t.Fatalf("expected client_id %s, got %s", testClientID, query.Get("client_id"))
	}
	if query.Get("state") == "" {
		t.Fatal("expected state query param")
	}
	if query.Get("redirect_uri") != "https://app.example.com/newton/callback" {
		t.Fatalf("unexpected redirect_uri %s", query.Get("redirect_uri"))
	}
}

func TestLoginRejectsSelfRedirect(t *testing.T) {
	auth := newTestAuth(t, newStubAPI(http.StatusOK, authCheckResponse{}))
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/newton/login?next=/newton/login", nil)
	rr := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(rr, req)

	if rr.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Result().StatusCode)
	}
}

func TestCallbackCreatesSessionCookieAndRedirects(t *testing.T) {
	auth := newTestAuth(t, newStubAPI(http.StatusOK, authCheckResponse{}))
	loginReq := httptest.NewRequest(http.MethodGet, "https://app.example.com/newton/login?next=/dashboard", nil)
	loginRR := httptest.NewRecorder()
	auth.LoginHandler().ServeHTTP(loginRR, loginReq)

	loginResp := loginRR.Result()
	stateCookie := mustCookie(t, loginResp, auth.config.StateCookieName)
	loginLocation, err := url.Parse(loginResp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := loginLocation.Query().Get("state")
	identity := buildTestCallbackAssertion(t, testCallbackSecret, testClientID, "https://api.example.com", callbackAssertion{
		Sub:                   "user-123",
		Aud:                   testClientID,
		Iss:                   "https://api.example.com",
		Authenticated:         true,
		Authorized:            true,
		ClientCacheTTLSeconds: 60,
		SessionTTLSeconds:     86400,
		PlatformToken:         "platform-token",
		Iat:                   time.Now().Unix(),
		Exp:                   time.Now().Add(time.Minute).Unix(),
		Nonce:                 "nonce",
	})

	callbackReq := httptest.NewRequest(http.MethodGet, "https://app.example.com/newton/callback?state="+url.QueryEscape(state)+"&identity="+url.QueryEscape(identity), nil)
	callbackReq.AddCookie(stateCookie)
	callbackRR := httptest.NewRecorder()

	auth.CallbackHandler().ServeHTTP(callbackRR, callbackReq)

	callbackResp := callbackRR.Result()
	if callbackResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", callbackResp.StatusCode)
	}
	if callbackResp.Header.Get("Location") != "/dashboard" {
		t.Fatalf("expected redirect to /dashboard, got %s", callbackResp.Header.Get("Location"))
	}
	sessionCookie := mustCookie(t, callbackResp, auth.config.SessionCookieName)
	if sessionCookie.Value == "" {
		t.Fatal("expected session cookie")
	}
	clearedStateCookie := mustCookie(t, callbackResp, auth.config.StateCookieName)
	if clearedStateCookie.MaxAge != 0 {
		t.Fatalf("expected cleared state cookie, got MaxAge=%d", clearedStateCookie.MaxAge)
	}
}

func TestCallbackRejectsStateMismatch(t *testing.T) {
	auth := newTestAuth(t, newStubAPI(http.StatusOK, authCheckResponse{}))
	loginReq := httptest.NewRequest(http.MethodGet, "https://app.example.com/newton/login?next=/", nil)
	loginRR := httptest.NewRecorder()
	auth.LoginHandler().ServeHTTP(loginRR, loginReq)

	loginResp := loginRR.Result()
	stateCookie := mustCookie(t, loginResp, auth.config.StateCookieName)
	identity := buildTestCallbackAssertion(t, testCallbackSecret, testClientID, "https://api.example.com", callbackAssertion{
		Sub:                   "user-123",
		Aud:                   testClientID,
		Iss:                   "https://api.example.com",
		Authenticated:         true,
		Authorized:            true,
		ClientCacheTTLSeconds: 60,
		SessionTTLSeconds:     86400,
		PlatformToken:         "platform-token",
		Iat:                   time.Now().Unix(),
		Exp:                   time.Now().Add(time.Minute).Unix(),
		Nonce:                 "nonce",
	})

	callbackReq := httptest.NewRequest(http.MethodGet, "https://app.example.com/newton/callback?state=wrong&identity="+url.QueryEscape(identity), nil)
	callbackReq.AddCookie(stateCookie)
	callbackRR := httptest.NewRecorder()

	auth.CallbackHandler().ServeHTTP(callbackRR, callbackReq)

	resp := callbackRR.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	clearedSession := mustCookie(t, resp, auth.config.SessionCookieName)
	if clearedSession.MaxAge != 0 {
		t.Fatalf("expected cleared session cookie, got MaxAge=%d", clearedSession.MaxAge)
	}
}

func TestProtectedRouteAllowsValidAuthenticatedSession(t *testing.T) {
	auth := newTestAuth(t, newStubAPI(http.StatusOK, authCheckResponse{
		Authenticated:         true,
		Authorized:            true,
		UID:                   "user-123",
		ClientCacheTTLSeconds: 60,
		SessionTTLSeconds:     86400,
		ShouldClearSession:    false,
	}))
	sessionCookie := buildValidSessionCookie(t, auth, "user-123", "platform-token", true, 86400)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/protected", nil)
	req.AddCookie(sessionCookie)
	rr := httptest.NewRecorder()

	auth.RequireAuthFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if !ok {
			t.Fatal("expected user in context")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"uid": user.UID})
	}).ServeHTTP(rr, req)

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Result().StatusCode)
	}
	if strings.TrimSpace(rr.Body.String()) != `{"uid":"user-123"}` {
		t.Fatalf("unexpected body %s", rr.Body.String())
	}
}

func TestProtectedRouteRejectsMissingSession(t *testing.T) {
	auth := newTestAuth(t, newStubAPI(http.StatusOK, authCheckResponse{}))
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/protected", nil)
	rr := httptest.NewRecorder()

	auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

	if rr.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Result().StatusCode)
	}
}

func TestProtectedRouteRejectsCorruptSessionAndClearsCookie(t *testing.T) {
	auth := newTestAuth(t, newStubAPI(http.StatusOK, authCheckResponse{}))
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/protected", nil)
	req.AddCookie(&http.Cookie{Name: auth.config.SessionCookieName, Value: "not-a-valid-cookie"})
	rr := httptest.NewRecorder()

	auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

	resp := rr.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	cleared := mustCookie(t, resp, auth.config.SessionCookieName)
	if cleared.MaxAge != 0 {
		t.Fatalf("expected cleared session cookie, got MaxAge=%d", cleared.MaxAge)
	}
}

func TestProtectedRouteServerRevokesSessionAndClearsCookie(t *testing.T) {
	auth := newTestAuth(t, newStubAPI(http.StatusOK, authCheckResponse{
		Authenticated:         false,
		Authorized:            false,
		UID:                   "user-123",
		ClientCacheTTLSeconds: 60,
		SessionTTLSeconds:     86400,
		ShouldClearSession:    true,
	}))
	sessionCookie := buildValidSessionCookie(t, auth, "user-123", "platform-token", true, 86400)
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/protected", nil)
	req.AddCookie(sessionCookie)
	rr := httptest.NewRecorder()

	auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

	resp := rr.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	cleared := mustCookie(t, resp, auth.config.SessionCookieName)
	if cleared.MaxAge != 0 {
		t.Fatalf("expected cleared session cookie, got MaxAge=%d", cleared.MaxAge)
	}
}

func TestProtectedRouteRejectsUnauthorizedUser(t *testing.T) {
	auth := newTestAuth(t, newStubAPI(http.StatusOK, authCheckResponse{
		Authenticated:         true,
		Authorized:            false,
		UID:                   "user-123",
		ClientCacheTTLSeconds: 60,
		SessionTTLSeconds:     86400,
		ShouldClearSession:    false,
	}))
	sessionCookie := buildValidSessionCookie(t, auth, "user-123", "platform-token", false, 86400)
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/protected", nil)
	req.AddCookie(sessionCookie)
	rr := httptest.NewRecorder()

	auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Result().StatusCode)
	}
}

func newTestAuth(t *testing.T, client *http.Client) *Auth {
	t.Helper()
	auth, err := New(Config{
		ClientID:       testClientID,
		ClientSecret:   testClientSecret,
		CallbackSecret: testCallbackSecret,
		NewtonAPIBase:  testNewtonAPIBase,
		HTTPClient:     client,
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func newStubAPI(status int, payload authCheckResponse) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rr := httptest.NewRecorder()
			rr.WriteHeader(status)
			_ = json.NewEncoder(rr).Encode(payload)
			return rr.Result(), nil
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func mustCookie(t *testing.T, resp *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %s not found", name)
	return nil
}

func buildValidSessionCookie(t *testing.T, auth *Auth, uid string, platformToken string, authorized bool, sessionTTLSeconds int) *http.Cookie {
	t.Helper()
	value, err := buildSessionCookieValue(uid, platformToken, authorized, sessionTTLSeconds, auth.config.SessionSigningSecret)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: auth.config.SessionCookieName, Value: value}
}

func buildTestCallbackAssertion(t *testing.T, callbackSecret string, clientID string, issuer string, payload callbackAssertion) string {
	t.Helper()
	key := sha256.Sum256([]byte(callbackSecret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	payload.Aud = clientID
	payload.Iss = issuer
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := randomBytes(12)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte(clientID)
	ciphertext := gcm.Seal(nil, nonce, payloadBytes, aad)
	return "v1." + b64URLEncode(nonce) + "." + b64URLEncode(ciphertext) + "." + b64URLEncode(aad)
}
