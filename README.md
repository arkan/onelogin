# onelogin

OneLogin client written in Go.

[![GoDoc](https://godoc.org/github.com/asobrien/onelogin?status.svg)](https://godoc.org/github.com/asobrien/onelogin)
[![Go Report Card](https://goreportcard.com/badge/github.com/asobrien/onelogin)](https://goreportcard.com/report/github.com/asobrien/onelogin)
[![Build Status](https://cloud.drone.io/api/badges/asobrien/onelogin/status.svg)](https://cloud.drone.io/asobrien/onelogin)

This is a fork of [arkan/onelogin](https://github.com/arkan/onelogin) that has been extended to
implement authentication methods that support MFA.

## Getting Started
```
go get github.com/asobrien/onelogin
```

## Register an application on OneLogin
First you need [to register a new application](https://admin.us.onelogin.com/api_credentials) to have `clientID` and `clientSecret` credentials.

At a minimum your credentials need "Authentication Only" scope in order to authenticate a user.
Querying the API, requires additional scopes which do not include the ability to authenticate.

If you need to authenticate users are programatically use the API, you will need to use two sets of
credentials and reinitialize the client. Only the "Manage All" scope has the ability to authenticate
users and interact with the API.

## Quickstart

### List Users
```
c := onelogin.New(clientID, clientSecret, "us_or_eu", team)
users, err := c.User.GetUsers(context.Background())
```

### Authenticate
Authenticate via username/password:

```
c := onelogin.New(clientID, clientSecret, "us_or_eu", team)
user, err := c.Authenticate(context.Background(), "username", "password")
```

Note this authentication method _always_ returns a `user`, if authentication if successful, 
regardless of whether MFA is required or not. To authenticate a user with strict MFA validation,
use the `AuthenticateWithVerify` function:

```
c := onelogin.New(clientID, clientSecret, "us_or_eu", team)
user, err := c.AuthenticateWithVerify(context.Background(), "username", "password", "Google Authenticator", "123456")
```

See the [documentation](https://godoc.org/github.com/asobrien/onelogin) for all the available commands.

## Licence
[MIT](./LICENSE)


