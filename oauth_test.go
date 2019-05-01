package onelogin

import (
	"testing"
	"time"
)

func TestIsExpired(t *testing.T) {
	// now is *always* Friday, February 13, 2009 11:31:30 PM
	now = func() time.Time { return time.Unix(1234567890, 0) }

	var uCreated time.Time
	var uExpiresIn int64

	tests := []struct {
		name      string
		created   time.Time
		expiresIn int64
		want      bool
	}{
		{
			"expired token",
			time.Unix(1234567000, 0),
			500,
			true,
		},
		{
			"unexpired token",
			time.Unix(1234567000, 0),
			1000,
			false,
		},
		{
			"nearly expired token",
			time.Unix(1234567000, 0),
			900, // expires in 10 sec from "now"
			false,
		},
		{
			"uninitialized token",
			uCreated,
			uExpiresIn,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &oauthToken{CreatedAt: tt.created, ExpiresIn: tt.expiresIn}
			got := token.isExpired()
			if got != tt.want {
				t.Errorf("got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestIsNearExpired(t *testing.T) {
	// now is *always* Friday, February 13, 2009 11:31:30 PM
	now = func() time.Time { return time.Unix(1234567890, 0) }

	var uCreated time.Time
	var uExpiresIn int64

	tests := []struct {
		name      string
		created   time.Time
		expiresIn int64
		want      bool // isExpired
	}{
		{
			"expired token",
			time.Unix(1234567000, 0),
			500,
			true,
		},
		{
			"unexpired token",
			time.Unix(1234567000, 0),
			1000,
			false,
		},
		{
			"nearly expired token",
			time.Unix(1234567000, 0),
			900, // expires in 10 sec from "now"
			true,
		},
		{
			"nearly unexpired token",
			time.Unix(1234567000, 0),
			951, // expires in 61 sec from "now"
			false,
		},
		{
			"uninitialized token",
			uCreated,
			uExpiresIn,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &oauthToken{CreatedAt: tt.created, ExpiresIn: tt.expiresIn}
			got := token.isNearExpired()
			if got != tt.want {
				t.Errorf("got: %v, want: %v", got, tt.want)
			}
		})
	}
}
