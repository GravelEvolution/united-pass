package registration

import "testing"

func TestBlockedRegistrationEmailDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		email   string
		blocked bool
	}{
		{name: "confirmed disposable domain", email: "person@agibar.icu", blocked: true},
		{name: "current mail tm domain", email: "person@emalupe.com", blocked: true},
		{name: "case insensitive", email: "person@AGIBAR.ICU", blocked: true},
		{name: "subdomain", email: "person@mail.agibar.icu", blocked: true},
		{name: "confirmed rickroll domain", email: "person@rickroll.icu", blocked: true},
		{name: "confirmed teens in times domain", email: "person@teensintimes.icu", blocked: true},
		{name: "isolated suspicious domain", email: "person@trinity3.icu", blocked: true},
		{name: "unrelated dot icu domain", email: "person@example.icu", blocked: false},
		{name: "mainstream provider", email: "person@outlook.com", blocked: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := isBlockedRegistrationEmail(test.email); got != test.blocked {
				t.Fatalf("isBlockedRegistrationEmail(%q) = %v, want %v", test.email, got, test.blocked)
			}
		})
	}
}

func TestValidateCreateRejectsBlockedEmailWithoutWeakeningOtherValidation(t *testing.T) {
	t.Parallel()

	input := CreateInput{
		Username:      "safe-user",
		DisplayName:   "Safe User",
		Email:         "person@agibar.icu",
		Password:      "Correct-Horse-9!",
		AcceptedTerms: true,
	}
	if err := ValidateCreate(input); err == nil {
		t.Fatal("ValidateCreate accepted an evidence-backed disposable email domain")
	}

	input.Email = "person@example.com"
	if err := ValidateCreate(input); err != nil {
		t.Fatalf("ValidateCreate rejected an unrelated valid email: %v", err)
	}
}
