package newtonauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type authHTTPClient struct {
	baseURL      string
	clientID     string
	clientSecret string
	timeout      time.Duration
	client       *http.Client
}

func newAuthHTTPClient(cfg Config) *authHTTPClient {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.AuthTimeout}
	}
	return &authHTTPClient{
		baseURL:      cfg.NewtonAPIBase,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		timeout:      cfg.AuthTimeout,
		client:       client,
	}
}

func (c *authHTTPClient) authCheck(uid string, platformToken string) (*authCheckResponse, error) {
	body, err := json.Marshal(map[string]string{
		"uid":            uid,
		"platform_token": platformToken,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/platform-auth/auth/check/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.clientID+":"+c.clientSecret)))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return &authCheckResponse{
			Authenticated:         false,
			Authorized:            false,
			UID:                   uid,
			ClientCacheTTLSeconds: 60,
			SessionTTLSeconds:     86400,
			ShouldClearSession:    true,
		}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("auth check failed with status %d", resp.StatusCode)
	}

	var result authCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *authHTTPClient) closeIdleConnections() {
	if transport, ok := c.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}
