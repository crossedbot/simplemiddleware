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
	AuthHeader     = "Authorization"
	ClaimUserId    = "uid"
	ClaimGrantType = "grant_type"
)

var (
	ErrClaimDataType     = errors.New("claim is not a string")
	ErrGrantTypeDataType = errors.New("grant type claim is not a string")
	ErrUserIdDataType    = errors.New("user ID claim is not a string")
)

var publicAuthKey []byte
var SetAuthPublicKey = func(pubKey []byte) {
	publicAuthKey = pubKey
}

var claimUserId = ClaimUserId
var SetClaimUserId = func(id string) {
	claimUserId = id
}

var claimGrantType = ClaimGrantType
var SetClaimGrantType = func(grant string) {
	claimGrantType = grant
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
		userId, err := getClaimFromRequest(claimUserId, r)
		if err != nil || userId == "" {
			server.JsonResponse(w, server.Error{
				Code:    server.ErrUnauthorizedCode,
				Message: "user identifier is missing or invalid",
			}, http.StatusUnauthorized)
			return
		}
		grantType, err := getClaimFromRequest(claimGrantType, r)
		if err != nil || grantType == "" {
			server.JsonResponse(w, server.Error{
				Code:    server.ErrUnauthorizedCode,
				Message: "grant type is missing or invalid",
			}, http.StatusUnauthorized)
			return
		}
		ctx := r.Context()
		ctx = context.WithValue(ctx, claimUserId, userId)
		ctx = context.WithValue(ctx, claimGrantType, grantType)
		r = r.WithContext(ctx)
		handler(w, r, p)
	})
	return server.NewHandler(h)
}

func getClaimFromRequest(claim string, r *http.Request) (string, error) {
	tknStr := authenticator.Extract(r)
	tkn, err := jwt.Parse(tknStr)
	if err != nil {
		return "", err
	}
	v, ok := tkn.Claims.Get(claim).(string)
	if !ok {
		return "", ErrClaimDataType
	}
	return v, nil

}
