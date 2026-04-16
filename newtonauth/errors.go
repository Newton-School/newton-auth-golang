package newtonauth

import "errors"

var (
	ErrInvalidState             = errors.New("invalid state")
	ErrInvalidCallbackAssertion = errors.New("invalid callback assertion")
	ErrInvalidSession           = errors.New("invalid session")
)
