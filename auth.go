package simplemiddleware

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/crossedbot/common/golang/server"
	jwt "github.com/crossedbot/simplejwt"
)

const (
	AuthHeader  = "Authorization"
	ClaimUserId = "uid"
)

var (
	ErrUserIdDataType = errors.New("user ID claim is not a string")
)

var publicAuthKey []byte
var SetAuthPublicKey = func(pubKey []byte) {
	publicAuthKey = pubKey
}

var claimUserId = ClaimUserId
var SetClaimUserId = func(id string) {
	claimUserId = id
}

var authOnce sync.Once
var authenticator = func() (mw Middleware) {
	authOnce.Do(func() {
		keyFunc := func(token *Token) ([]byte, error) {
			return publicAuthKey, nil
		}
		errFunc := func(w http.ResponseWriter, err error) {
			server.JsonResponse(w, server.Error{
				Code:    server.ErrUnauthorizedCode,
				Message: err.Error(),
			}, http.StatusUnauthorized)
		}
		mw = New(AuthHeader, keyFunc, errFunc)
	})
	return
}()

func Authorize(handler server.Handler) server.Handler {
	h := authenticator.Handle(func(w http.ResponseWriter, r *http.Request) {
		p := server.GetParameters(r.Context())
		userId, err := getUserIdFromRequest(r)
		if err != nil || userId == "" {
			server.JsonResponse(w, server.Error{
				Code:    server.ErrUnauthorizedCode,
				Message: "user identifier is missing or invalid",
			}, http.StatusUnauthorized)
			return
		}
		ctx := r.Context()
		r = r.WithContext(context.WithValue(ctx, claimUserId, userId))
		handler(w, r, p)
	})
	return server.NewHandler(h)
}

func getUserIdFromRequest(r *http.Request) (string, error) {
	tknStr := authenticator.Extract(r)
	tkn, err := jwt.Parse(tknStr)
	if err != nil {
		return "", err
	}
	userId, ok := tkn.Claims.Get(claimUserId).(string)
	if !ok {
		return "", ErrUserIdDataType
	}
	return userId, nil
}
