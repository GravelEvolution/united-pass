package registration

import (
	"errors"
	"testing"
)

func TestMailboxFamilyRateIdentityUsesOnlyReviewedProviderRules(t *testing.T) {
	for _, test := range []struct {
		email string
		want  string
	}{
		{"Victim.Name+campaign@gmail.com", "victimname@gmail.com"},
		{"victim.name+other@googlemail.com", "victimname@gmail.com"},
		{"Person+tag@Outlook.com", "person@outlook.com"},
		{"Person+tag@hotmail.com", "person@hotmail.com"},
		{"person.name+tag@example.com", ""},
		{"person.name@example.com", ""},
	} {
		if got := MailboxFamilyRateIdentity(test.email); got != test.want {
			t.Errorf("MailboxFamilyRateIdentity(%q)=%q, want %q", test.email, got, test.want)
		}
	}
}

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

func TestConfiguredEmailPolicyNormalizesAndClassifiesWithoutBroadTLDPatterns(t *testing.T) {
	policy, err := newEmailDomainPolicy(EmailDeliveryPolicyConfig{
		AdditionalBlockedDomains:       []string{"Blocked.Example"},
		AdditionalEstablishedDomains:   []string{"school.example"},
		AdditionalBlockedMXDomains:     []string{"mx.bad.example"},
		AdditionalEstablishedMXDomains: []string{"mx.good.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.profile("person@sub.blocked.example"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("configured subdomain block error = %v", err)
	}
	profile, err := policy.profile("person@dept.school.example")
	if err != nil || !profile.Established || profile.Domain != "dept.school.example" {
		t.Fatalf("profile = %#v err=%v", profile, err)
	}
	if _, err := newEmailDomainPolicy(EmailDeliveryPolicyConfig{AdditionalBlockedDomains: []string{"*.icu"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wildcard policy error = %v, want fail closed", err)
	}
	if _, err := newEmailDomainPolicy(EmailDeliveryPolicyConfig{AdditionalBlockedDomains: []string{"com"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("public-suffix-wide policy error = %v, want fail closed", err)
	}
	for _, suffix := range []string{"co.uk", "com.cn", "github.io"} {
		if _, err := newEmailDomainPolicy(EmailDeliveryPolicyConfig{AdditionalBlockedDomains: []string{suffix}}); !errors.Is(err, ErrUnavailable) {
			t.Errorf("public suffix %q policy error = %v, want fail closed", suffix, err)
		}
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
