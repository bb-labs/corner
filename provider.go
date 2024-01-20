package corner

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	TokenKey = "TOKEN"
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

	ClientID     string
	ClientSecret string
}

// NewProvider returns a new Provider, e.g. for Apple or Google.
func NewProvider(ctx context.Context, providerURL, clientID, clientSecret string) (*Provider, error) {
	provider, err := oidc.NewProvider(ctx, providerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider %q: %v", providerURL, err)
	}

	return &Provider{
		Provider:     provider,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}, nil
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *Provider) Redeem(ctx context.Context, code string) (context.Context, error) {
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     p.Endpoint(),
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %v", err)
	}

	return context.WithValue(context.Background(), TokenKey, token), nil
}

func (p *Provider) Refresh(ctx context.Context) (context.Context, error) {
	token := ctx.Value(TokenKey).(*oauth2.Token)
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     p.Endpoint(),
	}
	token, err := c.TokenSource(ctx, &oauth2.Token{RefreshToken: token.RefreshToken}).Token()
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %v", err)
	}

	return context.WithValue(context.Background(), TokenKey, token), nil
}

func (p *Provider) Verify(ctx context.Context) (bool, error) {
	token := ctx.Value(TokenKey).(*oauth2.Token)
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return false, fmt.Errorf("no id_token in token context")
	}

	_, err := p.Verifier(&oidc.Config{ClientID: p.ClientID}).Verify(ctx, raw)
	if err != nil {
		return false, fmt.Errorf("failed to verify id token: %v", err)
	}

	return true, nil
}
