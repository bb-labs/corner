package corner

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// AuthInterceptor returns a new unary server interceptors that performs per-request auth.
func AuthInterceptor(providers ...*Provider) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Get the metadata from the context
		meta, success := metadata.FromIncomingContext(ctx)
		if !success {
			return nil, fmt.Errorf("no metadata found in request")
		}

		// Get the auth code and refresh token from metadata
		authCode, authToken, authRefresh := GetAuthHeaders(meta)

		// Get the auth token from metadata, split on whitespace to get the token
		if len(authToken) == 0 {
			return nil, fmt.Errorf("no authorization token found in request")
		}

		// Loop through the providers, and verify the token
		for _, provider := range providers {
			// Verify the token
			verified, err := provider.Verify(ctx, authToken)
			if err != nil {
				return nil, err
			}

			if verified {
				// If we have a code (first sign in ever, or in a while), then redeem it for a refresh and id token.
				if len(authCode) > 0 {
					redeemed, err := provider.Redeem(ctx, authCode)
					if err != nil {
						return nil, err
					}

					return handler(SetAuthHeaders(redeemed), req)
				}
				return handler(SetAuthHeaders(ctx), req)
			}

			// If the token is expired, and we have a refresh token, refresh the session.
			if _, ok := err.(*oidc.TokenExpiredError); ok && len(authRefresh) > 0 {
				refreshed, err := provider.Refresh(ctx, authRefresh)
				if err != nil {
					return nil, err
				}

				return handler(SetAuthHeaders(refreshed), req)
			}
		}

		return nil, fmt.Errorf("no provider could verify the token")
	}
}
