package newtonauth

type User struct {
	UID        string
	Authorized bool
}

type AuthResult struct {
	Authenticated         bool
	Authorized            bool
	ShouldClearSession    bool
	User                  *User
	ClientCacheTTLSeconds int
	SessionTTLSeconds     int
}

type CallbackResult struct {
	RedirectURI           string
	User                  *User
	ClientCacheTTLSeconds int
	SessionTTLSeconds     int
}

type RedirectInstruction struct {
	Location string
}

type authCheckResponse struct {
	Authenticated         bool   `json:"authenticated"`
	Authorized            bool   `json:"authorized"`
	UID                   string `json:"uid"`
	ClientCacheTTLSeconds int    `json:"client_cache_ttl_seconds"`
	SessionTTLSeconds     int    `json:"session_ttl_seconds"`
	ShouldClearSession    bool   `json:"should_clear_session"`
}

type callbackAssertion struct {
	Sub                   string `json:"sub"`
	Aud                   string `json:"aud"`
	Iss                   string `json:"iss"`
	Authenticated         bool   `json:"authenticated"`
	Authorized            bool   `json:"authorized"`
	ClientCacheTTLSeconds int    `json:"client_cache_ttl_seconds"`
	SessionTTLSeconds     int    `json:"session_ttl_seconds"`
	PlatformToken         string `json:"platform_token"`
	Iat                   int64  `json:"iat"`
	Exp                   int64  `json:"exp"`
	Nonce                 string `json:"nonce"`
}

type sessionPayload struct {
	UID               string `json:"uid"`
	PlatformToken     string `json:"platform_token"`
	Authorized        bool   `json:"authorized"`
	SessionTTLSeconds int    `json:"session_ttl_seconds"`
	IssuedAt          int64  `json:"issued_at"`
	Nonce             string `json:"nonce"`
}

type statePayload struct {
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"`
	Exp         int64  `json:"exp"`
}
