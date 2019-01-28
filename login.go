package onelogin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// LoginService handles communications with login pages.
// https://developers.onelogin.com/api-docs/1/login-page/login-user-via-api
type LoginService struct {
	auth         *authResponse
	verifyDevice *string
	*service
}

// authParams is a struct that holds information required as part of requests that
// are used to authenticate a user.
type authParams struct {
	Username  string `json:"username_or_email"`
	Password  string `json:"password"`
	Subdomain string `json:"subdomain"`
}

// verifyFactorParams is a struct that holds information requeired in requests that
// verify a user's second-factor device.
type verifyFactorParams struct {
	DeviceID    string `json:"device_id"`
	StateToken  string `json:"state_token"`
	OTPToken    string `json:"otp_token"`
	DoNotNotify bool   `json:"do_not_notify"`
}

// authResponse is a struct where data in the authentication response can be
// marshalled into.
type authResponse struct {
	Status       string             `json:"status"`
	User         *AuthenticatedUser `json:"user"`
	ReturnToURL  string             `json:"return_to_url"`
	ExpiresAt    string             `json:"expires_at"`
	SessionToken string             `json:"session_token"`
	StateToken   string             `json:"state_token"`
	CallbackUrl  string             `json:"callback_url"`
	Devices      []*Devices         `json:"devices"`
}

// Devices contains registered user devices that can be used for MFA.
type Devices struct {
	DeviceType string `json:"device_type"`
	DeviceID   int64  `json:"device_id"`
}

// AuthenticatedUser contains user information for the Authentication.
type AuthenticatedUser struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}

// authenticate a user via the API. This function returns an *authResponse, which can be used to
// setup downstream verification with a second-factor device. The public method to authenticate a
// user is 'Authenticate' which returns user details upon successful authentication.
func (s *LoginService) authenticate(ctx context.Context, emailOrUsername string, password string) (*authResponse, error) {
	u := "/api/1/login/auth"

	a := authParams{
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

	var d []authResponse
	_, err = s.client.Do(ctx, req, &d)
	if err != nil {
		return nil, err
	}

	// auth is successful even if additional verification is required and a
	// state_token is issued.
	// https://developers.onelogin.com/api-docs/1/login-page/create-session-login-token
	if len(d) == 1 && (d[0].Status == "Authenticated" || d[0].StateToken != "") {
		s.auth = &d[0]
		return &d[0], nil
	}
	return nil, errors.New("authentication failed")
}

// verifyFactor handles calls the `verify_factor` endpoint. This function can be used to either directly
// verify the passcode from a factor device, or to generate a push to a device (e.g., SMS). Note that
// this function does not verify appropriate behavior, that is delegated to the API. For example, a
// 'Google Authenticator' device can not generate a push event.
// https://developers.onelogin.com/api-docs/1/login-page/verify-factor
func (s *LoginService) verifyFactor(ctx context.Context, device string, token string, doNotVerify bool) (*authResponse, error) {
	u := "/api/1/login/verify_factor"

	if s.auth == nil {
		return nil, errors.New("auth is nil, successful prior authentication required")
	}

	// Get the user's deviceID or error
	var deviceID string
	for _, d := range s.auth.Devices {
		if d.DeviceType == device {
			deviceID = strconv.FormatInt(d.DeviceID, 10)
			break
		}
	}
	if deviceID == "" {
		return nil, errors.New(fmt.Sprintf("verify device not found: %s", device))
	}

	s.verifyDevice = &device
	a := verifyFactorParams{
		DeviceID:    deviceID,
		StateToken:  s.auth.StateToken,
		OTPToken:    token,
		DoNotNotify: doNotVerify,
	}

	req, err := s.client.NewRequest("POST", u, a)
	if err != nil {
		return nil, err
	}

	if err := s.client.AddAuthorization(ctx, req); err != nil {
		return nil, err
	}

	var b bytes.Buffer
	_, err = s.client.Do(ctx, req, &b)
	if err != nil {
		return nil, err
	}

	// Read the raw response to determine if this is a 'pending' or a 'success' event.
	// Push verification generates 'pending' events, while devices with known passcodes will
	// generate 'success' events.
	var m responseMessage
	err = json.Unmarshal(b.Bytes(), &m)
	if err != nil {
		return nil, err
	}

	// If this is push verification, there is no response data
	if m.Status.Code == 200 && m.Status.Type == "pending" {
		return nil, nil
	}

	// Read the associate response data upon successful verification. This is either a
	// push event follow-up call or a verification of device with a known passcode.
	if m.Status.Code == 200 && m.Status.Type == "success" {
		var d []authResponse
		err = json.Unmarshal(m.Data, &d)
		if err != nil {
			return nil, err
		}
		if len(d) == 1 && d[0].Status == "Authenticated" {
			return &d[0], nil
		}
	}

	return nil, errors.New("verify factor failed")
}

// Authenticate a user with an email (or username) and a password. Note that a user can *always* successfully
// authenticate whether or not MFA is required. To check whether a user is able to verify with strict MFA compliance,
// AuthenticateWithVerify should be used.
func (s *LoginService) Authenticate(ctx context.Context, emailOrUsername string, password string) (*AuthenticatedUser, error) {
	auth, err := s.authenticate(ctx, emailOrUsername, password)
	if err != nil {
		return nil, err
	}
	return auth.User, nil
}

// AuthenticateWithVerify is used to strictly verify that a user is able both: authenticate with username and password AND to verify
// a user's second-factor device. If both conditions are not satisfied an error will be returned.
func (s *LoginService) AuthenticateWithVerify(ctx context.Context, emailOrUsername string, password string, device string, token string) (*AuthenticatedUser, error) {
	// authenticate to verify username and password and generate auth response
	_, err := s.authenticate(ctx, emailOrUsername, password)
	if err != nil {
		return nil, err
	}

	// regenerate authenticateResponse via the verify_factor endpoint
	authv, err := s.verifyFactor(ctx, device, token, true)
	if err != nil {
		return nil, err
	}
	return authv.User, nil
}

// AuthenticateWithPushVerify can be used with asynchronous factor methods (e.g., SMS). This function is first called to
// verify username/password authentication and then to generate a push event. Note that this function does not return
// user information if authentication is successful, a follow call via VerifyPushToken is required to verify the passcode
// generated in the push event and complete authentication.
func (s *LoginService) AuthenticateWithPushVerify(ctx context.Context, emailOrUsername string, password string, device string) error {
	_, err := s.authenticate(ctx, emailOrUsername, password)
	if err != nil {
		return err
	}

	// generate a push code
	_, err = s.verifyFactor(ctx, device, "", false) // empty token as push notify generates token
	return err
}

// VerifyPushToken is a follow-on to AuthenticateWithPushVerify and it used to complete second-factor authentication
// of an asynchronous device. If this is called prior to the generation of a token via AuthenticateWithPushVerify,
// an error will be returned.
func (s *LoginService) VerifyPushToken(ctx context.Context, token string) (*AuthenticatedUser, error) {
	if s.verifyDevice == nil {
		return nil, errors.New("no verifyDevice assigned, 'AuthenticateWithPush' needs to called before this function can be used")
	}

	auth, err := s.verifyFactor(ctx, *s.verifyDevice, token, true) // do not push notify on verify
	if err != nil {
		return nil, err
	}
	return auth.User, nil
}
