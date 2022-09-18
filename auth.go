package simplemiddleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/crossedbot/common/golang/server"
	jwt "github.com/crossedbot/simplejwt"
)

const (
	AuthHeader  = "Authorization"
	ClaimUserId = "uid"
	ClaimGrant  = "grant"
)

var (
	ErrClaimDataType  = errors.New("claim is not a string")
	ErrGrantDataType  = errors.New("grant claim is not a string")
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

var claimGrant = ClaimGrant
var SetClaimGrant = func(grant string) {
	claimGrant = grant
}

var authenticator = New(
	AuthHeader,
	func(token *Token) ([]byte, error) {
		return publicAuthKey, nil
	},
	func(w http.ResponseWriter, err error) {
		server.JsonResponse(w, server.Error{
			Code:    server.ErrUnauthorizedCode,
			Message: err.Error(),
		}, http.StatusUnauthorized)
	},
)
var SetAuthenticator = func(mw Middleware) {
	authenticator = mw
}

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
		grant, err := getClaimFromRequest(claimGrant, r)
		if err != nil || grant == "" {
			server.JsonResponse(w, server.Error{
				Code:    server.ErrUnauthorizedCode,
				Message: "grant is missing or invalid",
			}, http.StatusUnauthorized)
			return
		}
		ctx := r.Context()
		ctx = context.WithValue(ctx, claimUserId, userId)
		ctx = context.WithValue(ctx, claimGrant, grant)
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
