package onelogin

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/asobrien/onelogin"
	"github.com/stretchr/testify/assert"
)

func TestLoginService_VerifyPushToken(t *testing.T) {
	// assert an error is generated when no verifyDevice has been registered
	c := onelogin.New("clientID", "clientSecret", "us", "myteam")
	_, err := c.Login.VerifyPushToken(context.Background(), "token")
	assert.Error(t, err)
}

// Authenticate a user with a username (or email) and password. Authenticate is not
// strict with respect to MFA compliance: if the username/password are correct, a
// successful response will be generated even if user's policy requires MFA.
func ExampleLoginService_Authenticate() {
	c := onelogin.New("clientID", "clientSecret", "us", "myteam")
	user, err := c.Login.Authenticate(context.Background(), "username", "password")
	if err != nil {
		panic(err)
	}
	fmt.Println(user)
}

// AuthenticateWithVerify authenticates a user with a username (or email) and password,
// additionally a token from a second-factor device must be provided. This method can
// be used to ensure that a user is only authenticated if and only if the username
// and password are correct and valid second factor is provided.
func ExampleLoginService_AuthenticateWithVerify() {
	c := onelogin.New("clientID", "clientSecret", "us", "myteam")
	user, err := c.Login.AuthenticateWithVerify(context.Background(), "username", "password", "Google Authenticator", "123456")
	if err != nil {
		panic(err)
	}
	fmt.Println(user)
}

// AuthenticateWithPushVerify authenticates a user with a username (or email) and password,
// and then generates a token which is delivered to a client asynchronously (e.g., SMS). To
// complete the authentication, the token must be verified via a followup call with
// VerifyPushToken.
//
// In this example, the token is entered via a prompt and read from stdin.
func ExampleLoginService_AuthenticateWithPushVerify() {
	c := onelogin.New("clientID", "clientSecret", "us", "myteam")

	// Authenticate and generate a SMS token
	err := c.Login.AuthenticateWithPushVerify(context.Background(), "username", "password", "OneLogin SMS")
	if err != nil {
		panic(err)
	}

	// prompt for token
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Passcode: ")
	token, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}

	// verify token and conmplete authentication
	auth, err := c.Login.VerifyPushToken(context.Background(), token)
	if err != nil {
		panic(err)
	}
	fmt.Println(auth)
}
