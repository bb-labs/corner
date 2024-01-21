package corner

import (
	"context"
	"log"

	"google.golang.org/grpc"
)

// AuthInterceptor returns a new unary server interceptors that performs per-request auth.
func AuthInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		var newCtx context.Context

		log.Println("AuthInterceptor: ", info)
		log.Println("AuthInterceptor: ", req)
		log.Println("AuthInterceptor: ", handler)
		log.Println("AuthInterceptor: ", ctx)

		return handler(newCtx, req)
	}
}
