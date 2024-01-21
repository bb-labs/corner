package corner

import (
	"context"
	"log"

	"google.golang.org/grpc"
)

// AuthInterceptor returns a new unary server interceptors that performs per-request auth.
func AuthInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		log.Println("AuthInterceptor: ", info)
		log.Println("AuthInterceptor: ", req)
		log.Println("AuthInterceptor: ", handler)
		log.Println("AuthInterceptor: ", ctx)

		return handler(ctx, req)
	}
}

// // Grab the idToken
// auth := req.Header.Get("Authorization")
// if auth == "" {
// 	// No auth header provided, so don't attempt to load a session
// 	return nil, nil
// }
// token, err := j.findTokenFromHeader(auth)
// if err != nil {
// 	return nil, err
// }

// // Grab the auth code and refresh token, if provided
// code := req.Header.Get("X-Auth-Code")
// refresh := req.Header.Get("X-Auth-Refresh")

// // Create a session from the token
// session, err := j.provider.CreateSessionFromToken(req.Context(), token)

// logger.Print("session: ", session, "code: ", code, "refresh: ", refresh, "token: ", token)

// // If the token is expired, and we have a refresh token, refresh the session.
// if err != nil && strings.Contains(err.Error(), "oidc: token is expired") && refresh != "" {
// 	session.RefreshToken = refresh
// 	refreshed, err := j.provider.RefreshSession(req.Context(), session)
// 	if err != nil {
// 		fmt.Println("Error refreshing session: ", err)
// 		return nil, err
// 	}

// 	if refreshed {
// 		return session, nil
// 	}
// } else if err != nil { // We have an error and no refresh token, so return the error.
// 	return nil, err
// }

// // If we have a code (first sign in ever, or in a while), then redeem it for a refresh and id token.
// // Overwrite the session with the new session, in this case.
// if code != "" {
// 	session, err = j.provider.Redeem(req.Context(), "", code, "")
// 	if err != nil {
// 		logger.Printf("Error redeeming code: %s", err)
// 		return nil, err
// 	}
// 	logger.Println("Code redeemed!!!", code, "new session: ", session.RefreshToken, session.IDToken, session.AccessToken)
// 	return session, nil
// }

// // Otherwise, return the idToken session in the pure verification case.
// return session, nil
