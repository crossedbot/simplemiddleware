package simplemiddleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crossedbot/common/golang/server"
	"github.com/crossedbot/simplejwt"
	"github.com/crossedbot/simplejwt/algorithms"
	"github.com/stretchr/testify/require"
)

// generated by: $ openssl genrsa -out rsa2048.key 2048
/*
var testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwLHsIIZvkWYrexKCK08KyDU5uuK8mbzyzkDtK3AVZ1iHYfFV
+CQZHed/56to1E9IST6VmPn9Uz5D/mjiJeJVbqSxAZJjfNH0WS/O8Ul+z4vWX9NL
WlnHuWQUJWWGvvmkxbFBg1vf8qZi8NuCM/yNa7GTJaA3jBK/PlZnAvw6dymtWIjT
qxO7F8tawv8CHxNXyW9+Yexw/9fn8xx7ehWbhPHNe224A/Xn4SFCrqMikraHN64g
scxhwcUCYkcwO9OcK5VKLcDqtfEs50nsjKV/4yoAVdO0O7+nCqM0zcfu7DzN+3m0
kY/H8PaXbgp8e1BhnKZJnDKG5YafngMSHAKKaQIDAQABAoIBABy7auX+pawce+dB
/z7N7mGj7hO7szuJPPscG0Ea2VYrkSQ9hAAYAda/qga1PFBL8g9Z0ZyZyfgblK/e
m7niYbK5w9rkJQl7lN+njUfVGZ+AzlpDezzhnjI6hfZ9iPX462S+5XHcxSu9O4uG
b4eo5L1mIPa/SQkN0o5M+9cqHN2fiv0G7yhkwh0M9exACN/FFFotuy51ekZZkWvE
h11Rj1+BqDBPNbLLhhiDoGhcgOMmowkFvUB3o2wtNEZ3c+TbX604Rk7Iuarkmmse
HReXqzEaSXmyGEDI4eAHVNdBoJbqls0Oy10sK+sJiI4MUVMjSJfR9Kcy6SL9sNq1
IU8JFcECgYEA5qzd4B8neLEunIWWPwiMJGLQPbuI816hnIt7gsLTo2QvPEnr3JJA
j7snZ46crAlxGRAmVvvZKi5B2SbBlVVIo3Gh76TY0fedVl2PeolC1GeeAzHBdI05
6H4DXeb4sDvbt+5o/3eApJcMOrtkjeTe3skh7w1/O12G72tmkYSnhPUCgYEA1dme
r6kpSSosVMpMpivanBrODsPsAwfo3IC6JMig4+Au0ofDt43ChkEtEt+OV4cVRlfs
OJ/rx6qMr18NdG9P20PavZXSLxLVN+T8Wi5vERugQBoF1SP2HQuY5o1cFeln9Q07
qPJ2AzOhIAkuYkoJQLpNAzzfFpAZJ/YYkoF/JyUCgYBB4vhQzrU4fOtCW8mpYWid
7/do2orocIwaqaBynfFTRwdS4g5TZxa3tw4vPwWzAdNjBEDfMXo62RGH09ERNVXV
EVzelSg0+NPg2kJkDpafEqWIZgrKnpf+txeBF7rKo55Db/5fkaOV32rnz6SN/uRF
oA9oN2Oy8ijbc8LNJ6WtjQKBgQDLpYOycHs6i4jP7h50GEsEYZpdAUKd2Ehuw7+A
C/b7SqAMKPG+uKbIRwTvdikNPTyLUmtHuTNFXyq+Ttx3RxFbExEZfbU80shthAi0
sIdgWViP8rgfMzHKkyK2W2OYEj/HYySvTMYJYn9MDLI5M5wAIen47VzdFbh/D6Jy
0hMOaQKBgCGmozgoEAOPa0AtRBZpOae9Wd4O+RdS1kViWc/BbxXti/d43kYwPvQa
FERrxqgxSZPNe7OszDhjNZkkHcjJq4TWBOipaBTpCrwfvlbJyFVEAbA35QiOtEhU
jkJJL9Ks9iemrkMy7KFH5+dLIBErElN1jBByjxmgYvmssgf1/Vtr
-----END RSA PRIVATE KEY-----`

// generated by: $ openssl rsa -in rsa2048.key -outform PEM -pubout -out rsa2048.key.pub
var testPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwLHsIIZvkWYrexKCK08K
yDU5uuK8mbzyzkDtK3AVZ1iHYfFV+CQZHed/56to1E9IST6VmPn9Uz5D/mjiJeJV
bqSxAZJjfNH0WS/O8Ul+z4vWX9NLWlnHuWQUJWWGvvmkxbFBg1vf8qZi8NuCM/yN
a7GTJaA3jBK/PlZnAvw6dymtWIjTqxO7F8tawv8CHxNXyW9+Yexw/9fn8xx7ehWb
hPHNe224A/Xn4SFCrqMikraHN64gscxhwcUCYkcwO9OcK5VKLcDqtfEs50nsjKV/
4yoAVdO0O7+nCqM0zcfu7DzN+3m0kY/H8PaXbgp8e1BhnKZJnDKG5YafngMSHAKK
aQIDAQAB
-----END PUBLIC KEY-----`
*/

func TestAuthorize(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.Nil(t, err)
	claims := simplejwt.CustomClaims{
		claimUserId: "myuserid :3",
		claimGrant:  "givemeaccess!",
		"exp": time.Now().Local().Add(
			time.Hour * time.Duration(24),
		).Unix(),
	}
	tkn := simplejwt.New(claims, algorithms.AlgorithmRS256)
	bearer, err := tkn.Sign([]byte(testPrivateKey))
	require.Nil(t, err)
	hdr := "Authorization"
	bearer = fmt.Sprintf("Bearer %s", bearer)
	r.Header.Set(hdr, bearer)
	SetAuthPublicKey([]byte(testPublicKey))
	require.Nil(t, err)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner := Authorize(
			server.Handler(func(w http.ResponseWriter, r *http.Request, p server.Parameters) {
				w.WriteHeader(http.StatusOK)
			}),
		)
		p := server.GetParameters(r.Context())
		inner(w, r, p)
	})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "", rr.Body.String())
}

func TestGetClaimFromRequest(t *testing.T) {
	expectedUserId := "myuserid :3"
	expectedGrant := "givemeaccess!"
	claims := simplejwt.CustomClaims{
		claimUserId: expectedUserId,
		claimGrant:  expectedGrant,
		"exp": time.Now().Local().Add(
			time.Hour * time.Duration(24),
		).Unix(),
	}
	tkn, err := simplejwt.New(claims, algorithms.AlgorithmRS256).Sign([]byte(testPrivateKey))
	require.Nil(t, err)
	hdr := "Authorization"
	r := new(http.Request)
	r.Header = make(http.Header)
	r.Header.Set(hdr, fmt.Sprintf("Bearer %s", tkn))
	SetAuthPublicKey([]byte(testPublicKey))
	require.Nil(t, err)
	actual, err := getClaimFromRequest(claimUserId, r)
	require.Nil(t, err)
	require.Equal(t, expectedUserId, actual)
	actual, err = getClaimFromRequest(claimGrant, r)
	require.Nil(t, err)
	require.Equal(t, expectedGrant, actual)
}
