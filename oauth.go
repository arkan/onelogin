package onelogin

import (
	"context"
	"fmt"
	"time"
)

// OauthService handles communications with the authentication related methods on OneLogin.
type OauthService struct {
	*service
}

type issueTokenParams struct {
	GrantType    string `json:"grant_type"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type getTokenResponse struct {
	AccessToken  string `json:"access_token"`
	AccountID    int    `json:"account_id"`
	CreatedAt    string `json:"created_at"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// An oauthToken authenticates request to OneLogin.
// It is valid for 3600 seconds, and can be renewed.
type oauthToken struct {
	AccessToken string
	AccountID   int
	CreatedAt   time.Time
	ExpiresIn   int64
	TokenType   string

	refreshToken string
	client       *Client
}

// isExpired check the OauthToken validity.
func (t *oauthToken) isExpired() bool {
	return time.Now().UTC().Add(-time.Second * time.Duration(t.ExpiresIn)).After(t.CreatedAt.UTC())
}

// refresh the token. The current token gets updates with new valid values.
func (t *oauthToken) refresh(ctx context.Context) error {
	u := "/auth/oauth2/token"
	b := issueTokenParams{
		GrantType:    "refresh_token",
		AccessToken:  t.AccessToken,
		RefreshToken: t.refreshToken,
	}
	req, err := t.client.NewRequest("POST", u, b)
	if err != nil {
		return err
	}

	var r []getTokenResponse
	_, err = t.client.Do(ctx, req, &r)
	if err != nil {
		return err
	}

	createdAt, _ := time.Parse(time.RFC3339Nano, r[0].CreatedAt)
	t.AccessToken = r[0].AccessToken
	t.AccountID = r[0].AccountID
	t.CreatedAt = createdAt
	t.ExpiresIn = r[0].ExpiresIn
	t.TokenType = r[0].TokenType
	t.refreshToken = r[0].RefreshToken

	return nil
}

// getToken issues a new token.
func (s *OauthService) getToken(ctx context.Context) (*oauthToken, error) {
	u := "/auth/oauth2/token"

	b := issueTokenParams{
		GrantType: "client_credentials",
	}
	req, err := s.client.NewRequest("POST", u, b)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("client_id: %s, client_secret: %s", s.client.clientID, s.client.clientSecret))

	var r []getTokenResponse
	_, err = s.client.Do(ctx, req, &r)
	if err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339Nano, r[0].CreatedAt)
	token := &oauthToken{
		AccessToken:  r[0].AccessToken,
		AccountID:    r[0].AccountID,
		CreatedAt:    createdAt,
		ExpiresIn:    r[0].ExpiresIn,
		TokenType:    r[0].TokenType,
		refreshToken: r[0].RefreshToken,
		client:       s.client,
	}

	return token, nil
}
