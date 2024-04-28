package corner

type Headers map[string][]string

const (
	AuthCodeHeader          = "x-auth-code"
	AuthTokenHeader         = "authorization"
	AuthTokenHeaderInternal = "id_token"
	AuthRefreshHeader       = "x-auth-refresh"
)

type AuthHeaders struct {
	AuthCode    string
	AuthToken   string
	AuthRefresh string
}

func GetAuthHeaders(headers Headers) AuthHeaders {
	var authCode, authToken, authRefresh string

	if val, ok := headers[AuthCodeHeader]; ok {
		authCode = val[0]
	}
	if val, ok := headers[AuthTokenHeader]; ok {
		authToken = val[0]
	}
	if val, ok := headers[AuthRefreshHeader]; ok {
		authRefresh = val[0]
	}

	return AuthHeaders{AuthCode: authCode, AuthToken: authToken, AuthRefresh: authRefresh}
}
