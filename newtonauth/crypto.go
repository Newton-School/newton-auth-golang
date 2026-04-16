package newtonauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func b64URLEncode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func b64URLDecode(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func signValue(payload any, secret string) (string, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadValue := b64URLEncode(payloadBytes)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payloadValue))
	signature := hex.EncodeToString(mac.Sum(nil))
	return payloadValue + "." + signature, nil
}

func verifySignedValue(value string, secret string, out any) error {
	if value == "" || !strings.Contains(value, ".") {
		return ErrInvalidSession
	}
	lastDot := strings.LastIndex(value, ".")
	payloadValue := value[:lastDot]
	signature := value[lastDot+1:]

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payloadValue))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return ErrInvalidSession
	}

	payloadBytes, err := b64URLDecode(payloadValue)
	if err != nil {
		return ErrInvalidSession
	}
	if err := json.Unmarshal(payloadBytes, out); err != nil {
		return ErrInvalidSession
	}
	return nil
}

func decryptCallbackAssertion(identity string, callbackSecret string, clientID string, expectedIssuer string) (*callbackAssertion, error) {
	if identity == "" {
		return nil, ErrInvalidCallbackAssertion
	}
	parts := strings.Split(identity, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return nil, ErrInvalidCallbackAssertion
	}

	nonce, err := b64URLDecode(parts[1])
	if err != nil {
		return nil, ErrInvalidCallbackAssertion
	}
	ciphertext, err := b64URLDecode(parts[2])
	if err != nil {
		return nil, ErrInvalidCallbackAssertion
	}
	aad, err := b64URLDecode(parts[3])
	if err != nil {
		return nil, ErrInvalidCallbackAssertion
	}
	if string(aad) != clientID {
		return nil, fmt.Errorf("%w: assertion audience mismatch", ErrInvalidCallbackAssertion)
	}

	key := sha256.Sum256([]byte(callbackSecret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: assertion decryption failed", ErrInvalidCallbackAssertion)
	}

	var assertion callbackAssertion
	if err := json.Unmarshal(plaintext, &assertion); err != nil {
		return nil, ErrInvalidCallbackAssertion
	}

	nowTS := time.Now().Unix()
	switch {
	case assertion.Aud != clientID:
		return nil, fmt.Errorf("%w: assertion aud mismatch", ErrInvalidCallbackAssertion)
	case assertion.Iss != expectedIssuer:
		return nil, fmt.Errorf("%w: assertion issuer mismatch", ErrInvalidCallbackAssertion)
	case nowTS > assertion.Exp:
		return nil, fmt.Errorf("%w: assertion expired", ErrInvalidCallbackAssertion)
	case assertion.Iat > nowTS+30:
		return nil, fmt.Errorf("%w: assertion issued in future", ErrInvalidCallbackAssertion)
	case assertion.Sub == "" || assertion.PlatformToken == "":
		return nil, fmt.Errorf("%w: assertion missing required fields", ErrInvalidCallbackAssertion)
	default:
		return &assertion, nil
	}
}

func buildSessionPayload(uid string, platformToken string, authorized bool, sessionTTLSeconds int) (*sessionPayload, error) {
	nonce, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	return &sessionPayload{
		UID:               uid,
		PlatformToken:     platformToken,
		Authorized:        authorized,
		SessionTTLSeconds: sessionTTLSeconds,
		IssuedAt:          time.Now().Unix(),
		Nonce:             b64URLEncode(nonce),
	}, nil
}

func deriveIssuerFromBaseURL(baseURL string) (string, error) {
	req, err := httpNewRequest(baseURL)
	if err != nil {
		return "", err
	}
	if req.Scheme == "" || req.Host == "" {
		return "", errors.New("invalid newton api base")
	}
	return req.Scheme + "://" + req.Host, nil
}
