package newtonauth

import (
	"context"
	"errors"
	"net/http"
)

type HandlerOptions struct {
	UnauthenticatedHandler func(http.ResponseWriter, *http.Request, *AuthResult)
	UnauthorizedHandler    func(http.ResponseWriter, *http.Request, *AuthResult)
}

func (a *Auth) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextPath := r.URL.Query().Get("next")
		if nextPath == "" {
			nextPath = "/"
		}
		if err := a.validateLoginRedirectTarget(nextPath); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		redirect, stateCookieValue, err := a.BuildLoginRedirect(r, nextPath)
		if err != nil {
			http.Error(w, "failed to start login", http.StatusInternalServerError)
			return
		}
		setCookie(w, a.config.StateCookieName, stateCookieValue, 300)
		http.Redirect(w, r, redirect.Location, http.StatusFound)
	})
}

func (a *Auth) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, sessionCookieValue, err := a.HandleCallback(r)
		if err != nil {
			a.ClearSession(w)
			http.Error(w, "invalid auth callback", http.StatusBadRequest)
			return
		}
		setCookie(w, a.config.SessionCookieName, sessionCookieValue, result.SessionTTLSeconds)
		deleteCookie(w, a.config.StateCookieName)
		http.Redirect(w, r, result.RedirectURI, http.StatusFound)
	})
}

func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return a.RequireAuthWithOptions(next, HandlerOptions{})
}

func (a *Auth) RequireAuthFunc(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	handled := a.RequireAuth(http.HandlerFunc(next))
	return func(w http.ResponseWriter, r *http.Request) {
		handled.ServeHTTP(w, r)
	}
}

func (a *Auth) RequireAuthWithOptions(next http.Handler, opts HandlerOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, err := a.Authenticate(r)
		if err != nil {
			http.Error(w, "authentication failed", http.StatusInternalServerError)
			return
		}
		if !result.Authenticated {
			if result.ShouldClearSession {
				a.ClearSession(w)
			}
			handler := opts.UnauthenticatedHandler
			if handler == nil {
				handler = defaultUnauthenticatedHandler
			}
			handler(w, r, result)
			return
		}
		if !result.Authorized {
			if result.ShouldClearSession {
				a.ClearSession(w)
			}
			handler := opts.UnauthorizedHandler
			if handler == nil {
				handler = defaultUnauthorizedHandler
			}
			handler(w, r, result)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, result.User)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func defaultUnauthenticatedHandler(w http.ResponseWriter, r *http.Request, _ *AuthResult) {
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request, _ *AuthResult) {
	http.Error(w, "forbidden", http.StatusForbidden)
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case a.config.LoginPath:
			a.LoginHandler().ServeHTTP(w, r)
			return
		case a.config.CallbackPath:
			a.CallbackHandler().ServeHTTP(w, r)
			return
		default:
			next.ServeHTTP(w, r)
		}
	})
}

func IsInvalidCallbackError(err error) bool {
	return errors.Is(err, ErrInvalidCallbackAssertion) || errors.Is(err, ErrInvalidState)
}
