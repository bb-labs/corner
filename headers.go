package corner

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
	"google.golang.org/grpc/metadata"
)

type ContextKey int

const (
	TokenKey                ContextKey = iota
	AuthCodeHeader                     = "x-auth-code"
	AuthTokenHeader                    = "authorization"
	AuthTokenHeaderInternal            = "id_token"
	AuthRefreshHeader                  = "x-auth-refresh"
)

func GetOAuthToken(ctx context.Context) *oauth2.Token {
	return ctx.Value(TokenKey).(*oauth2.Token)
}

func GetAuthCode(headers metadata.MD) string {
	maybeAuthCode := headers.Get(AuthCodeHeader)

	if len(maybeAuthCode) == 0 {
		return ""
	}

	return maybeAuthCode[0]
}

func GetAuthToken(headers metadata.MD) string {
	maybeAuthToken := headers.Get(AuthTokenHeader)

	if len(maybeAuthToken) == 0 {
		return ""
	}

	return strings.Fields(maybeAuthToken[0])[1]
}

func GetAuthRefresh(headers metadata.MD) string {
	maybeAuthRefresh := headers.Get(AuthRefreshHeader)

	if len(maybeAuthRefresh) == 0 {
		return ""
	}

	return maybeAuthRefresh[0]
}

func GetAuthHeaders(headers metadata.MD) (string, string, string) {
	return GetAuthCode(headers), GetAuthToken(headers), GetAuthRefresh(headers)
}

func SetAuthHeaders(ctx context.Context) context.Context {
	token := GetOAuthToken(ctx)
	rawIDToken := token.Extra(AuthTokenHeaderInternal).(string)

	return metadata.NewIncomingContext(ctx, metadata.Pairs(
		AuthTokenHeader, fmt.Sprintf("Bearer %s", rawIDToken),
		AuthRefreshHeader, token.RefreshToken,
	))
}
