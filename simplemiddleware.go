package simplemiddleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/crossedbot/simplejwt"
)

var (
	// common errors
	ErrInvalidBearerToken = errors.New("invalid or missing bearer token")
)

// Token represents a JSON Web Token.
type Token jwt.Token

// KeyFunc is a function for returning the key of the JSON Web Token.
type KeyFunc func(token *Token) ([]byte, error)

// ErrFunc represets a callback function for handling errors when validating
// requests.
type ErrFunc func(w http.ResponseWriter, err error)

// Middleware represents an interface to a middleware object.
type Middleware interface {
	// Extract extracts a bearer token from a request.
	Extract(r *http.Request) (tkn string)

	// Handle wraps the given handler for validating a request via a JWT.
	Handle(handler http.HandlerFunc) http.HandlerFunc

	// SetErrFunc sets the function for handling errors during  JWT
	// validation.
	SetErrFunc(fn ErrFunc)

	// SetKeyFunc sets the function for retrieving the JWT's public key.
	SetKeyFunc(fn KeyFunc)
}

// middleware represent a middleware object; wrapping HTTP handlers for the
// purpose of validating JWTs.
type middleware struct {
	hdr     string
	keyFunc KeyFunc
	errFunc ErrFunc
}

// New returns a new Middleware object.
func New(header string, keyFunc KeyFunc, errFunc ErrFunc) Middleware {
	return &middleware{
		hdr:     header,
		keyFunc: keyFunc,
		errFunc: errFunc,
	}
}

// Extract extracts a bearer token from a request. If no bearer token is
// found, an empty string is returned.
func (m *middleware) Extract(r *http.Request) (tkn string) {
	h := r.Header.Get(m.hdr)
	if len(h) >= 7 && strings.EqualFold(h[:7], "BEARER ") {
		tkn = h[7:]
	}
	return
}

// Handle wraps the given handler for validating a request via a JWT.
func (m *middleware) Handle(handler http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bearer := m.Extract(r); bearer != "" {
			t, err := jwt.Parse(bearer)
			if err != nil {
				m.errFunc(w, fmt.Errorf("failed to parse token: %s", err))
				return
			}
			token := Token(*t)
			key, err := m.keyFunc(&token)
			if err != nil {
				m.errFunc(w, fmt.Errorf("failed to parse token: %s", err))
				return
			}
			if err := t.Valid(key); err == nil {
				handler(w, r)
			} else {
				m.errFunc(w, fmt.Errorf("invalid authorization token: %s", err))
				return
			}
		} else {
			m.errFunc(w, fmt.Errorf("missing authorization header: '%s'", m.hdr))
			return
		}
	})
}

func (m *middleware) SetErrFunc(fn ErrFunc) {
	m.errFunc = fn
}

func (m *middleware) SetKeyFunc(fn KeyFunc) {
	m.keyFunc = fn
}
