package onelogin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type SAMLService service

type samlRequestParams struct {
	OtpToken   string `json:"otp_token"`
	DeviceID   string `json:"device_id"`
	AppID      string `json:"app_id"`
	StateToken string `json:"state_token"`
}

type stateTokenParams struct {
	Username  string `json:"username_or_email"`
	Password  string `json:"password"`
	AppID     string `json:"app_id"`
	Subdomain string `json:"subdomain"`
}

type Device struct {
	Id               int64  `json:"device_id"`
	DeviceType       string `json:"device_type"`
	ApiHostName      string `json:"duo_api_hostname"`
	SignatureRequest string `json:"duo_sig_request"`
}

type SamlUser struct {
	ID            int64  `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	FirstName     string `json:"firstname"`
	LastName      string `json:"lastname"`
	IsMfaRequired bool
}

func (u *SamlUser) SetMfaRequirement(required bool) {
	u.IsMfaRequired = required
}

type MFAResponse struct {
	StateToken  string   `json:"state_token"`
	User        SamlUser `json:"user"`
	Devices     []Device `json:"devices"`
	CallbackUrl string   `json:"callback_url"`
}

type SAMLResponse struct {
	MFAResponse
	ErrorResponse
	Message string `json:"message"`
	Data    string `json:"data"`
}

type ErrorResponse struct {
	Name       string `json:"name"`
	StatusCode int    `json:"statusCode"`
}

func (s *SAMLService) SamlAssertion(ctx context.Context, username, password, appID string) (*MFAResponse, error) {
	u := "/api/2/saml_assertion"
	a := stateTokenParams{
		Username:  username,
		Password:  password,
		AppID:     appID,
		Subdomain: s.client.subdomain}

	req, err := s.client.NewRequest("POST", u, a)
	if err != nil {
		return nil, err
	}

	if err := s.client.AddAuthorization(ctx, req); err != nil {
		return nil, err
	}
	samlResp, err := s.client.DoSAMLAssertion(ctx, req)
	if err != nil {
		return nil, err
	}
	return &samlResp.MFAResponse, nil
}

func (s *SAMLService) VerifyFactor(ctx context.Context, otp, stateToken, appId, deviceId string) (string, error) {
	u := "/api/2/saml_assertion/verify_factor"
	a := samlRequestParams{
		OtpToken:   otp,
		DeviceID:   deviceId,
		AppID:      appId,
		StateToken: stateToken}
	req, err := s.client.NewRequest("POST", u, a)
	if err != nil {
		return "", err
	}

	if err := s.client.AddAuthorization(ctx, req); err != nil {
		return "", err
	}

	samlResp, err := s.client.DoSAMLAssertion(ctx, req)
	if err != nil {
		return "", err
	}

	if samlResp.Message == "Success" && samlResp.Data != "" {
		// Need to remove the double quote artifact from converting a json.RawMessage
		//  into a Go string
		return strings.Trim(samlResp.Data, "\""), nil
	}

	return "", errors.New("saml response does not contain an assertion")
}

// needs comments later
func (c *Client) DoSAMLAssertion(ctx context.Context, req *http.Request) (*SAMLResponse, error) {
	req = req.WithContext(ctx)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var samlResp *SAMLResponse = nil
	err = json.Unmarshal(body, samlResp)
	if err != nil {
		return nil, err
	}

	if samlResp == nil {
		return nil, errors.New("empy saml response from onelogin")
	}

	if samlResp.StatusCode == 400 || samlResp.StatusCode == 401 {
		return nil, fmt.Errorf("error from saml assertion onelogin: %v (%v) - %v", samlResp.Name, samlResp.StatusCode, samlResp.Message)
	}

	if samlResp.Message == "Success" && samlResp.Data != "" {
		// got back saml response
		fmt.Println("got successful saml response with assertion")
	}

	if samlResp.Message == "MFA is required for this user" {
		samlResp.User.SetMfaRequirement(true)
		fmt.Println("got successful saml response with user data")
	}

	return samlResp, nil
}
