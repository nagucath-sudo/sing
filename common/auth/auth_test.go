package auth

import "testing"

func TestAuthenticatorSupportsMultipleCredentialsPerUser(t *testing.T) {
	verifier := Verifier(NewAuthenticator([]User{
		{Username: "egress-a", Password: "client-a"},
		{Username: "egress-a", Password: "client-b"},
	}))
	if !verifier.Verify("egress-a", "client-a") || !verifier.Verify("egress-a", "client-b") {
		t.Fatal("multiple credentials for one user were not preserved")
	}
	if verifier.Verify("egress-a", "unknown") {
		t.Fatal("unknown credential was accepted")
	}
}
