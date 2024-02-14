package corner

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC specific provider URLs
const (
	AppleProviderURL = "https://appleid.apple.com"
)

// Provide implements various steps of the OpenID Connect flow.
type Provide interface {
	Verify(ctx context.Context) (bool, error)
	Redeem(ctx context.Context, code string) (context.Context, error)
	Refresh(ctx context.Context) (context.Context, error)
}

// Provider represents an OpenID Connect provider, with client credentials.
type Provider struct {
	*oidc.Provider
	*oidc.IDTokenVerifier
	*oauth2.Config
}

// NewAppleProvider returns a new Apple Provider.
func NewAppleProvider(ctx context.Context, clientID, clientSecret string) (*Provider, error) {
	return NewProvider(ctx, AppleProviderURL, clientID, clientSecret)
}

// NewProvider returns a new Provider, e.g. Apple or Google.
func NewProvider(ctx context.Context, providerURL, clientID, clientSecret string) (*Provider, error) {
	provider, err := oidc.NewProvider(ctx, providerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider %q: %v", providerURL, err)
	}

	return &Provider{
		Provider:        provider,
		IDTokenVerifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		Config:          &oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, Endpoint: provider.Endpoint()},
	}, nil
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *Provider) Redeem(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.Config.Exchange(ctx, code)
}

// Refresh exchanges the OAuth2 refresh token for an ID token
func (p *Provider) Refresh(ctx context.Context, refresh string) (*oauth2.Token, error) {
	return p.Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refresh}).Token()
}

func (p *Provider) Verify(ctx context.Context, token string) (*oidc.IDToken, error) {
	return p.IDTokenVerifier.Verify(ctx, token)
}
