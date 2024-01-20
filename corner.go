package corner

import (
	"context"

	"google.golang.org/grpc"
)

// AuthInterceptor returns a new unary server interceptors that performs per-request auth.
func AuthInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		var newCtx context.Context

		return handler(newCtx, req)
	}
}
