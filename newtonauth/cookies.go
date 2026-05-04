package newtonauth

import "time"

func buildStateCookieValue(state string, redirectURI string, secret string) (string, error) {
	return signValue(statePayload{
		State:       state,
		RedirectURI: redirectURI,
		Exp:         time.Now().Unix() + 300,
	}, secret)
}

func parseStateCookieValue(cookieValue string, secret string) (*statePayload, error) {
	var payload statePayload
	if err := verifySignedValue(cookieValue, secret, &payload); err != nil {
		return nil, err
	}
	if time.Now().Unix() > payload.Exp {
		return nil, ErrInvalidSession
	}
	return &payload, nil
}

func buildSessionCookieValue(uid string, platformToken string, authorized bool, sessionTTLSeconds int, secret string, clientID string) (string, error) {
	payload, err := buildSessionPayload(uid, platformToken, authorized, sessionTTLSeconds)
	if err != nil {
		return "", err
	}
	return encryptValue(payload, secret, []byte(clientID))
}

func parseSessionCookieValue(cookieValue string, secret string, clientID string) (*sessionPayload, error) {
	var payload sessionPayload
	if err := decryptValue(cookieValue, secret, []byte(clientID), &payload); err != nil {
		return nil, err
	}
	if payload.SessionTTLSeconds <= 0 || time.Now().Unix() > payload.IssuedAt+int64(payload.SessionTTLSeconds) {
		return nil, ErrInvalidSession
	}
	if payload.UID == "" || payload.PlatformToken == "" {
		return nil, ErrInvalidSession
	}
	return &payload, nil
}
