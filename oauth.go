package onelogin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// OauthService handles communications with the authentication related methods on OneLogin.
type OauthService service

type authenticationParams struct {
	Username  string `json:"username_or_email"`
	Password  string `json:"password"`
	Subdomain string `json:"subdomain"`
}

type issueTokenParams struct {
	GrantType    string `json:"grant_type"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type GetTokenResponse struct {
	AccessToken  string `json:"access_token"`
	AccountID    int    `json:"account_id"`
	CreatedAt    string `json:"created_at"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

type GenerateTokenResponse struct {
	GetTokenResponse
	Status struct {
		Error   bool   `json:"error"`
		Code    int    `json:"code"`
		Type    string `json:"type"`
		Message string `json:"message`
	} `json:"status"`
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

// getToken issues a new token.
func (s *OauthService) getToken(ctx context.Context) (*oauthToken, error) {
	u := "/auth/oauth2/v2/token"

	b := issueTokenParams{
		GrantType: "client_credentials",
	}
	req, err := s.client.NewRequest("POST", u, b)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("client_id: %s, client_secret: %s", s.client.clientID, s.client.clientSecret))

	generatedToken, err := s.client.DoOAuthGenerate(ctx, req)
	if err != nil {
		return nil, err
	}

	if generatedToken.Status.Error {
		return nil, fmt.Errorf("onelogin oauth error: %v (%v) - %v", generatedToken.Status.Type, generatedToken.Status.Code, generatedToken.Status.Message)
	}

	createdAt, _ := time.Parse(time.RFC3339Nano, generatedToken.CreatedAt)
	token := &oauthToken{
		AccessToken:  generatedToken.AccessToken,
		AccountID:    generatedToken.AccountID,
		CreatedAt:    createdAt,
		ExpiresIn:    generatedToken.ExpiresIn,
		TokenType:    generatedToken.TokenType,
		refreshToken: generatedToken.RefreshToken,
		client:       s.client,
	}

	return token, nil
}

type AuthenticateResponse struct {
	Status struct {
		Error   bool   `json:"error"`
		Code    int    `json:"code"`
		Type    string `json:"type"`
		Message string `json:"message`
	} `json:"status"`
	Data []struct {
		Status       string            `json:"status"`
		User         AuthenticatedUser `json:"user"`
		ReturnToURL  string            `json:"return_to_url"`
		ExpiresAt    string            `json:"expires_at"`
		SessionToken string            `json:"session_token"`
		StateToken   string            `json:"state_token"`
		Devices      []Device          `json:"devices"`
	} `json:"data"`
}

// AuthenticatedUser contains user information for the Authentication.
type AuthenticatedUser struct {
	ID            int64  `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	FirstName     string `json:"firstname"`
	LastName      string `json:"lastname"`
	Devices       []Device
	IsMfaRequired bool
}

func (u *AuthenticatedUser) SetMfaRequirement(required bool) {
	u.IsMfaRequired = required
}

func (u *AuthenticatedUser) SetDevices(devices []Device) {
	u.Devices = devices
}

// Authenticate a user from an email(or username) and a password.
func (s *OauthService) Authenticate(ctx context.Context, emailOrUsername string, password string) (*AuthenticatedUser, error) {
	u := "/api/1/login/auth"

	a := authenticationParams{
		Username:  emailOrUsername,
		Password:  password,
		Subdomain: s.client.subdomain,
	}

	req, err := s.client.NewRequest("POST", u, a)
	if err != nil {
		return nil, err
	}

	if err := s.client.AddAuthorization(ctx, req); err != nil {
		return nil, err
	}

	loginResp, err := s.client.DoLogin(ctx, req)
	if err != nil {
		return nil, err
	}

	if loginResp.Status.Error {
		return nil, fmt.Errorf("login failed for onelogin: %v (%v) - %v", loginResp.Status.Type, loginResp.Status.Code, loginResp.Status.Message)
	}

	if len(loginResp.Data) <= 0 {
		return nil, errors.New("onelogin returned no user for login action")
	}

	if loginResp.Data[0].Status == "Authenticated" {
		return &loginResp.Data[0].User, nil
	}

	if loginResp.Status.Message == "MFA is required for this user" && len(loginResp.Data[0].Devices) > 0 {
		return &loginResp.Data[0].User, nil
	}

	return nil, fmt.Errorf("no valid user recieve from onelogin login")
}

func (c *Client) DoOAuthGenerate(ctx context.Context, req *http.Request) (*GenerateTokenResponse, error) {
	req = req.WithContext(ctx)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var oauthResp *GenerateTokenResponse = nil
	err = json.Unmarshal(body, oauthResp)
	if err != nil {
		return nil, err
	}

	if oauthResp == nil {
		return nil, errors.New("OAuth response is nil")
	}

	return oauthResp, nil

}

func (c *Client) DoLogin(ctx context.Context, req *http.Request) (*AuthenticateResponse, error) {
	req = req.WithContext(ctx)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var loginResp *AuthenticateResponse = nil
	err = json.Unmarshal(body, loginResp)
	if err != nil {
		return nil, err
	}

	if loginResp == nil {
		return nil, errors.New("login response is nil")
	}

	return loginResp, nil
}
