package corner

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// AuthInterceptor provides various middleware that authenticate requests using the given providers.
type AuthInterceptor struct {
	Providers []*Provider
}

// New returns a new AuthInterceptor that uses the given providers to authenticate requests.
func New(providers ...*Provider) *AuthInterceptor {
	return &AuthInterceptor{Providers: providers}
}

// AuthMiddleware returns a new middleware that performs per-request auth.
func (cb *AuthInterceptor) GinAuthenticator(ctx *gin.Context) {
	// Get the auth token
	token, err := cb.authenticate(ctx, Headers(ctx.Request.Header))
	if err != nil {
		ctx.AbortWithStatusJSON(401, gin.H{"error": fmt.Sprintf("unable to authenticate request: %v", err)})
		return
	}

	// Set auth headers
	rawIDToken := token.Extra(AuthTokenHeaderInternal).(string)
	ctx.Request.Header.Set(AuthTokenHeader, fmt.Sprintf("Bearer %s", rawIDToken))
	ctx.Request.Header.Set(AuthRefreshHeader, token.RefreshToken)

	ctx.Next()
}

// UnaryServerInterceptor returns a new grpc unary server interceptor that authenticates requests using the given providers.
func (cb *AuthInterceptor) UnaryServerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	// Get the metadata from the context
	meta, success := metadata.FromIncomingContext(ctx)
	if !success {
		return nil, fmt.Errorf("no metadata found in request")
	}

	// Get the auth token
	token, err := cb.authenticate(ctx, Headers(meta))
	if err != nil {
		return nil, fmt.Errorf("unable to authenticate request: %v", err)
	}

	// Set auth headers
	rawIDToken, ok := token.Extra(AuthTokenHeaderInternal).(string)
	if !ok {
		fmt.Println("token: ", token.Extra(AuthTokenHeaderInternal))
		return nil, fmt.Errorf("unable to extract internal id token")
	}

	grpc.SetHeader(ctx, metadata.Pairs(
		AuthTokenHeader, fmt.Sprintf("Bearer %s", rawIDToken),
		AuthRefreshHeader, token.RefreshToken,
	))

	return handler(ctx, req)
}

func (cb *AuthInterceptor) authenticate(ctx context.Context, headers Headers) (*oauth2.Token, error) {
	// Get the auth headers
	authHeaders := GetAuthHeaders(headers)

	// Get the auth token from metadata, split on whitespace to get the token
	if len(authHeaders.AuthToken) == 0 {
		return nil, fmt.Errorf("no authorization token found in request")
	}

	// Loop through the providers, and verify the token
	for _, provider := range cb.Providers {
		// Verify the token
		idToken, err := provider.Verify(ctx, authHeaders.AuthToken)
		if err != nil {
			return nil, err
		}

		if idToken != nil {
			// If we have a code (first sign in ever, or in a while), then redeem it for a refresh and id token.
			if len(authHeaders.AuthCode) > 0 {
				return provider.Redeem(ctx, authHeaders.AuthCode)
			}

			return (&oauth2.Token{}).WithExtra(map[string]string{
				AuthTokenHeaderInternal: authHeaders.AuthToken,
			}), nil
		}

		// If the token is expired, and we have a refresh token, refresh the session.
		if _, ok := err.(*oidc.TokenExpiredError); ok && len(authHeaders.AuthRefresh) > 0 {
			return provider.Refresh(ctx, authHeaders.AuthRefresh)
		}
	}

	return nil, fmt.Errorf("no provider could verify the token")
}
