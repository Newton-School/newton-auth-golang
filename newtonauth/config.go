package newtonauth

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	defaultLoginPath         = "/newton/login"
	defaultCallbackPath      = "/newton/callback"
	defaultSessionCookieName = "newton_session"
	defaultStateCookieName   = "newton_state"
	defaultCacheMaxMB        = 1
	defaultAuthTimeout       = 10 * time.Second
)

type Config struct {
	ClientID             string
	ClientSecret         string
	CallbackSecret       string
	NewtonAPIBase        string
	SessionSigningSecret string
	LoginPath            string
	CallbackPath         string
	SessionCookieName    string
	StateCookieName      string
	CacheMaxMB           int
	AuthTimeout          time.Duration
	HTTPClient           *http.Client
}

func (c Config) withDefaults() Config {
	if c.LoginPath == "" {
		c.LoginPath = defaultLoginPath
	}
	if c.CallbackPath == "" {
		c.CallbackPath = defaultCallbackPath
	}
	if c.SessionCookieName == "" {
		c.SessionCookieName = defaultSessionCookieName
	}
	if c.StateCookieName == "" {
		c.StateCookieName = defaultStateCookieName
	}
	if c.CacheMaxMB == 0 {
		c.CacheMaxMB = defaultCacheMaxMB
	}
	if c.AuthTimeout == 0 {
		c.AuthTimeout = defaultAuthTimeout
	}
	if c.SessionSigningSecret == "" {
		c.SessionSigningSecret = c.ClientSecret
	}
	c.NewtonAPIBase = strings.TrimRight(c.NewtonAPIBase, "/")
	return c
}

func (c Config) validate() error {
	switch {
	case c.ClientID == "":
		return errors.New("client id is required")
	case c.ClientSecret == "":
		return errors.New("client secret is required")
	case c.CallbackSecret == "":
		return errors.New("callback secret is required")
	case c.NewtonAPIBase == "":
		return errors.New("newton api base is required")
	case !strings.HasPrefix(c.LoginPath, "/"):
		return errors.New("login path must start with /")
	case !strings.HasPrefix(c.CallbackPath, "/"):
		return errors.New("callback path must start with /")
	case c.CacheMaxMB < 0:
		return errors.New("cache max mb must be >= 0")
	case c.AuthTimeout <= 0:
		return errors.New("auth timeout must be > 0")
	default:
		return nil
	}
}
