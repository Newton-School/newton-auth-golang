package newtonauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type Auth struct {
	config       Config
	httpClient   *authHTTPClient
	cache        *lruCache
	issuer       string
	callbackPath string
}

func New(cfg Config) (*Auth, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	issuer, err := deriveIssuerFromBaseURL(cfg.NewtonAPIBase)
	if err != nil {
		return nil, err
	}
	return &Auth{
		config:       cfg,
		httpClient:   newAuthHTTPClient(cfg),
		cache:        newLRUCache(cfg.CacheMaxMB),
		issuer:       issuer,
		callbackPath: cfg.CallbackPath,
	}, nil
}

func (a *Auth) Config() Config {
	return a.config
}

func (a *Auth) Authenticate(r *http.Request) (*AuthResult, error) {
	cookie, err := r.Cookie(a.config.SessionCookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return &AuthResult{}, nil
		}
		return nil, err
	}

	session, err := parseSessionCookieValue(cookie.Value, a.config.SessionSigningSecret)
	if err != nil {
		return &AuthResult{
			Authenticated:      false,
			Authorized:         false,
			ShouldClearSession: true,
		}, nil
	}

	if cached, ok := a.cache.get(session.UID); ok {
		result := authCheckToResult(*cached, session)
		return result, nil
	}

	authCheck, err := a.httpClient.authCheck(session.UID, session.PlatformToken)
	if err != nil {
		return nil, err
	}
	a.cache.set(session.UID, *authCheck)
	return authCheckToResult(*authCheck, session), nil
}

func (a *Auth) BuildLoginRedirect(r *http.Request, redirectURI string) (*RedirectInstruction, string, error) {
	stateBytes, err := randomBytes(24)
	if err != nil {
		return nil, "", err
	}
	state := b64URLEncode(stateBytes)
	postLoginRedirect := redirectURI
	if postLoginRedirect == "" {
		postLoginRedirect = currentPath(r)
	}
	stateCookieValue, err := buildStateCookieValue(state, postLoginRedirect, a.config.SessionSigningSecret)
	if err != nil {
		return nil, "", err
	}
	callbackURL := buildCallbackURL(r, a.config.CallbackPath)
	location := appendQueryParams(a.config.NewtonAPIBase+"/platform-auth/login", map[string]string{
		"client_id":    a.config.ClientID,
		"state":        state,
		"redirect_uri": callbackURL,
	})
	return &RedirectInstruction{Location: location}, stateCookieValue, nil
}

func (a *Auth) HandleCallback(r *http.Request) (*CallbackResult, string, error) {
	stateParam := r.URL.Query().Get("state")
	identity := r.URL.Query().Get("identity")

	stateCookie, err := r.Cookie(a.config.StateCookieName)
	if err != nil {
		return nil, "", ErrInvalidState
	}
	stateData, err := parseStateCookieValue(stateCookie.Value, a.config.SessionSigningSecret)
	if err != nil {
		return nil, "", ErrInvalidState
	}
	if stateParam != stateData.State {
		return nil, "", ErrInvalidState
	}

	assertion, err := decryptCallbackAssertion(identity, a.config.CallbackSecret, a.config.ClientID, a.issuer)
	if err != nil {
		return nil, "", err
	}

	sessionCookieValue, err := buildSessionCookieValue(
		assertion.Sub,
		assertion.PlatformToken,
		assertion.Authorized,
		assertion.SessionTTLSeconds,
		a.config.SessionSigningSecret,
	)
	if err != nil {
		return nil, "", err
	}

	a.cache.set(assertion.Sub, authCheckResponse{
		Authenticated:         assertion.Authenticated,
		Authorized:            assertion.Authorized,
		UID:                   assertion.Sub,
		ClientCacheTTLSeconds: assertion.ClientCacheTTLSeconds,
		SessionTTLSeconds:     assertion.SessionTTLSeconds,
		ShouldClearSession:    false,
	})

	return &CallbackResult{
		RedirectURI: stateData.RedirectURI,
		User: &User{
			UID:        assertion.Sub,
			Authorized: assertion.Authorized,
		},
		ClientCacheTTLSeconds: assertion.ClientCacheTTLSeconds,
		SessionTTLSeconds:     assertion.SessionTTLSeconds,
	}, sessionCookieValue, nil
}

func (a *Auth) ClearSession(w http.ResponseWriter) {
	deleteCookie(w, a.config.SessionCookieName)
	deleteCookie(w, a.config.StateCookieName)
}

func (a *Auth) CloseIdleConnections() {
	a.httpClient.closeIdleConnections()
}

func authCheckToResult(data authCheckResponse, session *sessionPayload) *AuthResult {
	result := &AuthResult{
		Authenticated:         data.Authenticated,
		Authorized:            data.Authorized,
		ShouldClearSession:    data.ShouldClearSession,
		ClientCacheTTLSeconds: data.ClientCacheTTLSeconds,
		SessionTTLSeconds:     data.SessionTTLSeconds,
	}
	if result.SessionTTLSeconds == 0 && session != nil {
		result.SessionTTLSeconds = session.SessionTTLSeconds
	}
	if data.Authenticated {
		result.User = &User{
			UID:        session.UID,
			Authorized: data.Authorized,
		}
	}
	return result
}

func appendQueryParams(rawURL string, params map[string]string) string {
	u, err := httpNewRequest(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	for key, value := range params {
		q.Set(key, value)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func buildCallbackURL(r *http.Request, callbackPath string) string {
	scheme := forwardedScheme(r)
	host := forwardedHost(r)
	return scheme + "://" + host + callbackPath
}

func currentPath(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}
	return r.URL.Path + "?" + r.URL.RawQuery
}

func forwardedScheme(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); value != "" {
		parts := strings.Split(value, ",")
		return strings.TrimSpace(parts[0])
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func forwardedHost(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); value != "" {
		parts := strings.Split(value, ",")
		return strings.TrimSpace(parts[0])
	}
	if r.Host != "" {
		return r.Host
	}
	return "localhost"
}

func setCookie(w http.ResponseWriter, name string, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func deleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   0,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) validateLoginRedirectTarget(nextPath string) error {
	if nextPath == a.config.LoginPath {
		return fmt.Errorf("invalid login redirect target")
	}
	return nil
}
