package dreamupdelegation

import (
	"regexp"
	"time"
	"unicode/utf8"
)

// MaxParticipantTTL keeps a mobile request assertion useful only long enough
// to cross the local service boundary. It is not a replacement session.
const MaxParticipantTTL = 20 * time.Second

// ParticipantSigner issues request-bound assertions for the DreamUP
// participant APIs. It deliberately has no administrative capability or role
// claims and may not be used for /internal or /admin routes.
type ParticipantSigner struct {
	keyring *Keyring
	config  SignerConfig
}

type ParticipantAssertion struct {
	// Subject is the already-linked OIDC provider subject, never a caller
	// supplied profile field or local United Pass database ID.
	Subject      string
	JWTID        string
	Method       string
	PathAndQuery string
	BodySHA256   string
	// HeaderSHA256 binds the concurrency and idempotency controls which are
	// security-relevant to participant mutations. Raw header values are never
	// placed in the bearer token.
	HeaderSHA256 string
	// ResumeUpload is present only for the participant's own binary resume
	// upload. The bytes never transit United Pass: the worker verifies that
	// the received bytes match BodySHA256 and this signed metadata.
	ResumeUpload *ResumeUploadMetadata
}

type ResumeUploadMetadata struct {
	FileName    string
	ContentType string
	ByteSize    int64
}

type participantClaims struct {
	registeredClaims
	ActorKind         string `json:"actor_kind"`
	Method            string `json:"htm"`
	PathAndQuery      string `json:"htu"`
	BodySHA256        string `json:"body_sha256"`
	HeaderSHA256      string `json:"headers_sha256"`
	ResumeFileName    string `json:"resume_file_name,omitempty"`
	ResumeContentType string `json:"resume_content_type,omitempty"`
	ResumeByteSize    int64  `json:"resume_byte_size,omitempty"`
}

var participantPathPattern = regexp.MustCompile(`^/api/v1/events/[a-z0-9][a-z0-9-]{0,79}/me/(application(?:/(?:submit|withdraw|reopen|resume))?|review-progress|admission(?:/(?:entry-code|group-qr))?|checkin|seat-confirm|team(?:/(?:join|leave|dissolve|captain-transfer|requests|plaza-applications|invite-by-email)|/invite-code/rotate|/requests/[A-Za-z0-9._:-]{1,255}/decision)?|feedback|sponsorship-enquiries|emergency-reports|code-resolutions|available-assets|asset-reservations(?:/[A-Za-z0-9._:-]{1,255})?|personal-assets)$`)

func NewParticipantSigner(keyring *Keyring, config SignerConfig) (*ParticipantSigner, error) {
	if err := validateSignerConfig(keyring, config); err != nil || config.TTL > MaxParticipantTTL {
		return nil, ErrInvalidSignerConfig
	}
	return &ParticipantSigner{keyring: keyring, config: config}, nil
}

func (s *ParticipantSigner) SignParticipant(input ParticipantAssertion) (SignedAssertion, error) {
	if s == nil || s.keyring == nil || s.config.Now == nil {
		return SignedAssertion{}, ErrInvalidSignerConfig
	}
	now := s.config.Now().UTC().Truncate(time.Second)
	if !validIssuedAt(now.Unix()) || !safeIDPattern.MatchString(input.Subject) || !requestIDPattern.MatchString(input.JWTID) || !validParticipantRequest(input) {
		return SignedAssertion{}, ErrInvalidAssertion
	}
	claims := participantClaims{
		registeredClaims: newRegisteredClaims(s.config, input.Subject, input.JWTID, now, s.config.TTL),
		ActorKind:        "participant", Method: input.Method, PathAndQuery: input.PathAndQuery, BodySHA256: input.BodySHA256, HeaderSHA256: input.HeaderSHA256,
	}
	if input.ResumeUpload != nil {
		claims.ResumeFileName = input.ResumeUpload.FileName
		claims.ResumeContentType = input.ResumeUpload.ContentType
		claims.ResumeByteSize = input.ResumeUpload.ByteSize
	}
	return s.keyring.signedAssertion(claims)
}

func validParticipantRequest(input ParticipantAssertion) bool {
	if !validRequestBinding(input.Method, input.PathAndQuery, input.BodySHA256) || !hexDigestPattern.MatchString(input.HeaderSHA256) || !participantPathPattern.MatchString(input.PathAndQuery) {
		return false
	}
	if isParticipantResumePath(input.PathAndQuery) {
		if input.Method == "GET" {
			return input.ResumeUpload == nil && input.BodySHA256 == SHA256Digest(nil)
		}
		return input.Method == "PUT" && validResumeUploadMetadata(input.ResumeUpload)
	}
	if input.ResumeUpload != nil {
		return false
	}
	// Participant routes deliberately have a small fixed surface. GETs are
	// read-only; mutations are only the existing applicant-owned operations.
	switch {
	case input.Method == "GET" && (pathAndQueryHasSuffix(input.PathAndQuery, "/application") || pathAndQueryHasSuffix(input.PathAndQuery, "/review-progress") || pathAndQueryHasSuffix(input.PathAndQuery, "/admission") || pathAndQueryHasSuffix(input.PathAndQuery, "/admission/group-qr") || pathAndQueryHasSuffix(input.PathAndQuery, "/checkin") || pathAndQueryHasSuffix(input.PathAndQuery, "/seat-confirm") || pathAndQueryHasSuffix(input.PathAndQuery, "/available-assets") || pathAndQueryHasSuffix(input.PathAndQuery, "/asset-reservations") || pathAndQueryHasSuffix(input.PathAndQuery, "/personal-assets") || isParticipantTeamRoot(input.PathAndQuery)):
		return input.BodySHA256 == SHA256Digest(nil)
	case input.Method == "PUT" && pathAndQueryHasSuffix(input.PathAndQuery, "/application"):
		return true
	case input.Method == "POST" && (pathAndQueryHasSuffix(input.PathAndQuery, "/submit") || pathAndQueryHasSuffix(input.PathAndQuery, "/withdraw") || pathAndQueryHasSuffix(input.PathAndQuery, "/reopen") || pathAndQueryHasSuffix(input.PathAndQuery, "/admission/entry-code") || pathAndQueryHasSuffix(input.PathAndQuery, "/seat-confirm") || pathAndQueryHasSuffix(input.PathAndQuery, "/code-resolutions") || pathAndQueryHasSuffix(input.PathAndQuery, "/asset-reservations") || pathAndQueryHasSuffix(input.PathAndQuery, "/emergency-reports") || isParticipantTeamPostRoute(input.PathAndQuery) || containsParticipantContactSubmission(input.PathAndQuery)):
		return true
	case input.Method == "DELETE" && (pathAndQueryHasSuffix(input.PathAndQuery, "/admission/entry-code") || participantAssetReservationItemPattern.MatchString(input.PathAndQuery)):
		return true
	case input.Method == "PATCH" && isParticipantTeamRoot(input.PathAndQuery):
		return true
	default:
		return false
	}
}

func isParticipantResumePath(path string) bool {
	return pathAndQueryHasSuffix(path, "/application/resume")
}

func validResumeUploadMetadata(value *ResumeUploadMetadata) bool {
	if value == nil || value.ByteSize < 1 || value.ByteSize > 5*1024*1024 || !utf8.ValidString(value.FileName) || len(value.FileName) == 0 || len(value.FileName) > 255 || hasForbiddenResumeFilenameCharacter(value.FileName) {
		return false
	}
	switch value.ContentType {
	case "application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return true
	default:
		return false
	}
}

func hasForbiddenResumeFilenameCharacter(value string) bool {
	for _, character := range value {
		if character <= 0x1f || character == 0x7f || (character >= 0x202a && character <= 0x202e) || (character >= 0x2066 && character <= 0x2069) {
			return true
		}
	}
	return false
}

// ParticipantHeadersSHA256 binds the only state-control headers supported by
// the applicant API. Header names and separators are fixed to remove
// serialization ambiguity between United Pass and the Worker.
func ParticipantHeadersSHA256(ifMatch, idempotencyKey string) string {
	return requestHeadersSHA256(ifMatch, idempotencyKey)
}

func pathAndQueryHasSuffix(path, suffix string) bool {
	return len(path) >= len(suffix) && path[len(path)-len(suffix):] == suffix
}
func isParticipantTeamRoot(path string) bool {
	return participantTeamRootPattern.MatchString(path)
}

func isParticipantTeamPostRoute(path string) bool {
	return participantTeamPostPattern.MatchString(path)
}

func containsParticipantContactSubmission(path string) bool {
	return participantContactSubmissionPattern.MatchString(path)
}

var participantTeamRootPattern = regexp.MustCompile(`/me/team$`)
var participantTeamPostPattern = regexp.MustCompile(`/me/team(?:/(?:join|leave|dissolve|captain-transfer|requests|plaza-applications|invite-by-email)|/invite-code/rotate|/requests/[A-Za-z0-9._:-]{1,255}/decision)?$`)
var participantContactSubmissionPattern = regexp.MustCompile(`/me/(?:feedback|sponsorship-enquiries)$`)
var participantAssetReservationItemPattern = regexp.MustCompile(`/me/asset-reservations/[A-Za-z0-9._:-]{1,255}$`)
