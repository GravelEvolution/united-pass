package postgres

import (
	"net/url"
	"testing"
)

func TestRewriteURLForInsecureMode_SetsSslmodeDisable(t *testing.T) {
	input := "postgres://user:pass@host:5432/db?sslmode=require"
	got, err := RewriteURLForInsecureMode(input)
	if err != nil {
		t.Fatalf("RewriteURLForInsecureMode returned error: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse result URL: %v", err)
	}
	if got := u.Query().Get("sslmode"); got != "disable" {
		t.Errorf("sslmode = %q, want %q", got, "disable")
	}
}

func TestRewriteURLForInsecureMode_PreservesOtherParams(t *testing.T) {
	input := "postgres://user:pass@host:5432/db?sslmode=verify-full&application_name=test&connect_timeout=10"
	got, err := RewriteURLForInsecureMode(input)
	if err != nil {
		t.Fatalf("RewriteURLForInsecureMode returned error: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse result URL: %v", err)
	}
	if got := u.Query().Get("sslmode"); got != "disable" {
		t.Errorf("sslmode = %q, want %q", got, "disable")
	}
	if got := u.Query().Get("application_name"); got != "test" {
		t.Errorf("application_name = %q, want %q", got, "test")
	}
	if got := u.Query().Get("connect_timeout"); got != "10" {
		t.Errorf("connect_timeout = %q, want %q", got, "10")
	}
}

func TestRewriteURLForInsecureMode_AlreadyDisable(t *testing.T) {
	input := "postgres://user:pass@host:5432/db?sslmode=disable"
	got, err := RewriteURLForInsecureMode(input)
	if err != nil {
		t.Fatalf("RewriteURLForInsecureMode returned error: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse result URL: %v", err)
	}
	if got := u.Query().Get("sslmode"); got != "disable" {
		t.Errorf("sslmode = %q, want %q", got, "disable")
	}
}

func TestRewriteURLForInsecureMode_InvalidURL(t *testing.T) {
	// url.Parse is very lenient, so use a control character that forces
	// a parse error.
	_, err := RewriteURLForInsecureMode("postgres://\x00")
	if err == nil {
		t.Fatal("RewriteURLForInsecureMode should return error for invalid URL")
	}
}
