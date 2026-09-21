package dreamupdelegation

import (
	"strings"
	"testing"
	"time"
)

func TestParticipantSignerBindsOnlyAllowedApplicantRequest(t *testing.T) {
	keyring, public := loadDelegationTestKeyring(t)
	signer, err := NewParticipantSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup-mobile-api", TTL: 15 * time.Second, ClockSkew: 2 * time.Second, Now: func() time.Time { return delegationTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	input := ParticipantAssertion{Subject: "zitadel-subject-01", JWTID: "req_participant_01", Method: "PUT", PathAndQuery: "/api/v1/events/dreamup-shanghai/me/application", BodySHA256: SHA256Digest([]byte(`{"schemaVersion":"dreamup-application-v2"}`)), HeaderSHA256: ParticipantHeadersSHA256(`"2"`, "")}
	signed, err := signer.SignParticipant(input)
	if err != nil {
		t.Fatal(err)
	}
	if !signed.ExpiresAt.Equal(delegationTestNow.Add(15 * time.Second)) {
		t.Fatalf("expires=%s", signed.ExpiresAt)
	}
	_, claims := verifyDelegationToken(t, signed.Token, public)
	assertExactClaimNames(t, claims, []string{"iss", "aud", "sub", "iat", "nbf", "exp", "jti", "actor_kind", "htm", "htu", "body_sha256", "headers_sha256"})
	assertStringClaim(t, claims, "actor_kind", "participant")
	assertStringClaim(t, claims, "sub", input.Subject)
	assertStringClaim(t, claims, "htu", input.PathAndQuery)
}

func TestParticipantSignerRejectsAdminAndUnboundPaths(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, err := NewParticipantSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup-mobile-api", TTL: 15 * time.Second, Now: func() time.Time { return delegationTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	cases := []ParticipantAssertion{
		{Subject: "subject-1", JWTID: "req_participant_02", Method: "GET", PathAndQuery: "/internal/v1/events/id/applications", BodySHA256: SHA256Digest(nil), HeaderSHA256: ParticipantHeadersSHA256("", "")},
		{Subject: "subject-1", JWTID: "req_participant_03", Method: "POST", PathAndQuery: "/api/v1/events/dreamup/me/application/decision", BodySHA256: SHA256Digest([]byte(`{}`)), HeaderSHA256: ParticipantHeadersSHA256("", "")},
		{Subject: "subject-1", JWTID: "req_participant_04", Method: "GET", PathAndQuery: "/api/v1/events/dreamup/me/application", BodySHA256: SHA256Digest([]byte(`{}`)), HeaderSHA256: ParticipantHeadersSHA256("", "")},
	}
	for _, input := range cases {
		if _, err := signer.SignParticipant(input); err == nil {
			t.Fatalf("unsafe assertion accepted: %+v", input)
		}
	}
}

func TestParticipantSignerPermitsOnlyExplicitParticipantTeamRoutes(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, err := NewParticipantSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup-mobile-api", TTL: 15 * time.Second, Now: func() time.Time { return delegationTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	base := ParticipantAssertion{Subject: "subject-1", JWTID: "req_participant_team", HeaderSHA256: ParticipantHeadersSHA256(`"1"`, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}
	for _, test := range []struct{ method, path, body string }{
		{"GET", "/api/v1/events/dreamup-shanghai/me/team", ""},
		{"PATCH", "/api/v1/events/dreamup-shanghai/me/team", `{"name":"月石"}`},
		{"POST", "/api/v1/events/dreamup-shanghai/me/team", `{"name":"月石"}`},
		{"POST", "/api/v1/events/dreamup-shanghai/me/team/invite-by-email", `{"email":"teammate@example.test"}`},
		{"POST", "/api/v1/events/dreamup-shanghai/me/team/requests/request_1/decision", `{"decision":"accept"}`},
	} {
		base.Method, base.PathAndQuery, base.BodySHA256 = test.method, test.path, SHA256Digest([]byte(test.body))
		if _, err := signer.SignParticipant(base); err != nil {
			t.Fatalf("team route rejected: %s %s: %v", test.method, test.path, err)
		}
	}
	for _, path := range []string{
		"/api/v1/events/dreamup-shanghai/me/teams",
		"/api/v1/events/dreamup-shanghai/me/team/admin-export",
		"/api/v1/events/dreamup-shanghai/me/team/requests/request_1/escalate",
	} {
		base.Method, base.PathAndQuery, base.BodySHA256 = "POST", path, SHA256Digest([]byte(`{}`))
		if _, err := signer.SignParticipant(base); err == nil {
			t.Fatalf("unrecognised team route accepted: %s", path)
		}
	}
	for _, test := range []struct{ method, path string }{
		{"GET", "/api/v1/events/dreamup-shanghai/me/team/requests"},
		{"GET", "/api/v1/events/dreamup-shanghai/me/team/invite-by-email"},
		{"PATCH", "/api/v1/events/dreamup-shanghai/me/team/join"},
		{"PATCH", "/api/v1/events/dreamup-shanghai/me/team/requests/request_1/decision"},
	} {
		base.Method, base.PathAndQuery, base.BodySHA256 = test.method, test.path, SHA256Digest(nil)
		if _, err := signer.SignParticipant(base); err == nil {
			t.Fatalf("team method/path combination accepted: %s %s", test.method, test.path)
		}
	}
}

func TestParticipantSignerPermitsOnlyParticipantContactSubmissions(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, err := NewParticipantSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup-mobile-api", TTL: 15 * time.Second, Now: func() time.Time { return delegationTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	base := ParticipantAssertion{Subject: "subject-1", JWTID: "req_participant_contact", Method: "POST", BodySHA256: SHA256Digest([]byte(`{"content":"页面无法提交"}`)), HeaderSHA256: ParticipantHeadersSHA256("", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}
	for _, path := range []string{"/api/v1/events/dreamup-shanghai/me/feedback", "/api/v1/events/dreamup-shanghai/me/sponsorship-enquiries", "/api/v1/events/dreamup-shanghai/me/emergency-reports"} {
		base.PathAndQuery = path
		if _, err := signer.SignParticipant(base); err != nil {
			t.Fatalf("contact route rejected: %s: %v", path, err)
		}
	}
	base.PathAndQuery = "/api/v1/events/dreamup-shanghai/me/contact-submissions"
	if _, err := signer.SignParticipant(base); err == nil {
		t.Fatal("unrecognised contact route accepted")
	}
}

func TestParticipantSignerPermitsOnlyExplicitScanAndReservationContracts(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, err := NewParticipantSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup-mobile-api", TTL: 15 * time.Second, Now: func() time.Time { return delegationTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	base := ParticipantAssertion{Subject: "subject-1", JWTID: "req_scan_asset_contract", HeaderSHA256: ParticipantHeadersSHA256(`"1"`, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}
	for _, test := range []struct{ method, path, body string }{
		{"POST", "/api/v1/events/dreamup-shanghai/me/code-resolutions", `{"code":"opaque-local-only"}`},
		{"GET", "/api/v1/events/dreamup-shanghai/me/available-assets", ""},
		{"GET", "/api/v1/events/dreamup-shanghai/me/asset-reservations", ""},
		{"POST", "/api/v1/events/dreamup-shanghai/me/asset-reservations", `{"assetId":"asset_1","quantity":1}`},
		{"DELETE", "/api/v1/events/dreamup-shanghai/me/asset-reservations/reservation_1", ""},
		{"GET", "/api/v1/events/dreamup-shanghai/me/personal-assets", ""},
	} {
		base.Method, base.PathAndQuery, base.BodySHA256 = test.method, test.path, SHA256Digest([]byte(test.body))
		if _, err := signer.SignParticipant(base); err != nil {
			t.Fatalf("participant contract rejected: %s %s: %v", test.method, test.path, err)
		}
	}
	for _, test := range []struct{ method, path string }{
		{"GET", "/api/v1/events/dreamup-shanghai/me/code-resolutions"},
		{"POST", "/api/v1/events/dreamup-shanghai/me/available-assets"},
		{"PATCH", "/api/v1/events/dreamup-shanghai/me/asset-reservations/reservation_1"},
		{"DELETE", "/api/v1/events/dreamup-shanghai/me/asset-reservations/reservation_1/force"},
		{"GET", "/api/v1/events/dreamup-shanghai/me/personal-assets/other"},
		{"POST", "/api/v1/events/dreamup-shanghai/me/inspection-attempts"},
	} {
		base.Method, base.PathAndQuery, base.BodySHA256 = test.method, test.path, SHA256Digest(nil)
		if _, err := signer.SignParticipant(base); err == nil {
			t.Fatalf("unsafe participant contract accepted: %s %s", test.method, test.path)
		}
	}
}

func TestParticipantSignerPermitsOnlyAcceptedParticipantAdmissionRoutes(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, err := NewParticipantSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup-mobile-api", TTL: 15 * time.Second, Now: func() time.Time { return delegationTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	base := ParticipantAssertion{Subject: "subject-1", JWTID: "req_participant_admission", HeaderSHA256: ParticipantHeadersSHA256("", "")}
	for _, test := range []struct {
		method string
		path   string
		body   string
	}{
		{"GET", "/api/v1/events/dreamup-shanghai/me/admission", ""},
		{"GET", "/api/v1/events/dreamup-shanghai/me/admission/group-qr", ""},
		{"GET", "/api/v1/events/dreamup-shanghai/me/checkin", ""},
		{"GET", "/api/v1/events/dreamup-shanghai/me/seat-confirm", ""},
		{"POST", "/api/v1/events/dreamup-shanghai/me/admission/entry-code", "{}"},
		{"DELETE", "/api/v1/events/dreamup-shanghai/me/admission/entry-code", "{}"},
		{"POST", "/api/v1/events/dreamup-shanghai/me/seat-confirm", `{"name":"Ada","idcard":"110101199001011234"}`},
	} {
		base.Method, base.PathAndQuery, base.BodySHA256 = test.method, test.path, SHA256Digest([]byte(test.body))
		if _, err := signer.SignParticipant(base); err != nil {
			t.Fatalf("admission route rejected: %s %s: %v", test.method, test.path, err)
		}
	}
	base.Method, base.PathAndQuery, base.BodySHA256 = "POST", "/api/v1/events/dreamup-shanghai/me/admission/group-qr", SHA256Digest([]byte("{}"))
	if _, err := signer.SignParticipant(base); err == nil {
		t.Fatal("group QR route accepted a non-GET method")
	}
}

func TestParticipantSignerBindsBinaryResumeMetadataToOnlyTheResumeRoute(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, err := NewParticipantSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup-mobile-api", TTL: 15 * time.Second, Now: func() time.Time { return delegationTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	input := ParticipantAssertion{
		Subject: "subject-1", JWTID: "req_participant_resume", Method: "PUT", PathAndQuery: "/api/v1/events/dreamup-shanghai/me/application/resume",
		BodySHA256: SHA256Digest([]byte("portable document")), HeaderSHA256: ParticipantHeadersSHA256("", ""),
		ResumeUpload: &ResumeUploadMetadata{FileName: "resume.pdf", ContentType: "application/pdf", ByteSize: 17},
	}
	if _, err := signer.SignParticipant(input); err != nil {
		t.Fatalf("valid resume upload rejected: %v", err)
	}
	input.ResumeUpload.FileName = strings.Repeat("简", 85)
	if len(input.ResumeUpload.FileName) != 255 {
		t.Fatalf("test filename bytes=%d", len(input.ResumeUpload.FileName))
	}
	if _, err := signer.SignParticipant(input); err != nil {
		t.Fatalf("255-byte Chinese resume filename rejected: %v", err)
	}
	input.ResumeUpload.FileName += "a"
	if _, err := signer.SignParticipant(input); err == nil {
		t.Fatal("256-byte Chinese resume filename accepted")
	}
	input.ResumeUpload.FileName = "resume.pdf"
	read := ParticipantAssertion{
		Subject: "subject-1", JWTID: "req_participant_resume_read", Method: "GET", PathAndQuery: "/api/v1/events/dreamup-shanghai/me/application/resume",
		BodySHA256: SHA256Digest(nil), HeaderSHA256: ParticipantHeadersSHA256("", ""),
	}
	if _, err := signer.SignParticipant(read); err != nil {
		t.Fatalf("valid resume metadata read rejected: %v", err)
	}
	read.BodySHA256 = SHA256Digest([]byte(`{"unexpected":true}`))
	if _, err := signer.SignParticipant(read); err == nil {
		t.Fatal("resume metadata read with a request body accepted")
	}
	input.ResumeUpload = nil
	if _, err := signer.SignParticipant(input); err == nil {
		t.Fatal("resume upload without signed metadata accepted")
	}
	input.ResumeUpload = &ResumeUploadMetadata{FileName: "resume.pdf", ContentType: "application/pdf", ByteSize: 17}
	input.PathAndQuery = "/api/v1/events/dreamup-shanghai/me/application"
	if _, err := signer.SignParticipant(input); err == nil {
		t.Fatal("resume metadata accepted on ordinary application route")
	}
}

func TestParticipantSignerPermitsOnlyTheWorkerReviewProgressRoute(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, err := NewParticipantSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup-mobile-api", TTL: 15 * time.Second, Now: func() time.Time { return delegationTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	input := ParticipantAssertion{
		Subject: "subject-1", JWTID: "req_participant_review_progress", Method: "GET", PathAndQuery: "/api/v1/events/dreamup-shanghai/me/review-progress",
		BodySHA256: SHA256Digest(nil), HeaderSHA256: ParticipantHeadersSHA256("", ""),
	}
	if _, err := signer.SignParticipant(input); err != nil {
		t.Fatalf("worker review-progress route rejected: %v", err)
	}
	input.PathAndQuery = "/api/v1/events/dreamup-shanghai/me/application/review-progress"
	if _, err := signer.SignParticipant(input); err == nil {
		t.Fatal("nonexistent nested review-progress route accepted")
	}
}
