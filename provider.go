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

	internal Config
}

// Config represents the configuration for an OpenID Connect provider.
type Config struct {
	// Force usage of Provider specific constructors
	providerURL string

	// Client credentials
	ClientID     string
	ClientSecret string

	// Skip various checks
	SkipChecks bool
}

// NewAppleProvider returns a new Apple Provider.
func NewAppleProvider(ctx context.Context, config Config) (*Provider, error) {
	config.providerURL = AppleProviderURL
	return newProvider(ctx, config)
}

// NewProvider returns a new Provider, e.g. Apple or Google.
func newProvider(ctx context.Context, config Config) (*Provider, error) {
	provider, err := oidc.NewProvider(ctx, config.providerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider %q: %v", config.providerURL, err)
	}

	return &Provider{
		Provider: provider,
		IDTokenVerifier: provider.Verifier(&oidc.Config{
			ClientID:                   config.ClientID,
			SkipExpiryCheck:            config.SkipChecks,
			SkipIssuerCheck:            config.SkipChecks,
			SkipClientIDCheck:          config.SkipChecks,
			InsecureSkipSignatureCheck: config.SkipChecks,
		}),
		Config: &oauth2.Config{
			Endpoint:     provider.Endpoint(),
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
		},
		internal: config,
	}, nil
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *Provider) Redeem(ctx context.Context, code string) (*oauth2.Token, error) {
	if p.internal.SkipChecks {
		return &oauth2.Token{}, nil
	}
	return p.Config.Exchange(ctx, code)
}

// Refresh exchanges the OAuth2 refresh token for an ID token
func (p *Provider) Refresh(ctx context.Context, refresh string) (*oauth2.Token, error) {
	if p.internal.SkipChecks {
		return &oauth2.Token{}, nil
	}
	return p.Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refresh}).Token()
}

func (p *Provider) Verify(ctx context.Context, token string) (*oidc.IDToken, error) {
	return p.IDTokenVerifier.Verify(ctx, token)
}
