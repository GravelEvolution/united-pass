// Package dreamupadmin provides the bounded, non-retrying HTTP boundary from
// United Pass to DreamUP's private administration API.
package dreamupadmin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	pathpkg "path"
	"regexp"
	"strings"
	"time"
	"unicode"

	requestcontext "github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	admincontract "github.com/GravelEvolution/united-pass/backend/internal/dreamupadmin"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/identityaccess"
)

const (
	// MaxResponseBytes is the default ceiling for every DreamUP response.
	MaxResponseBytes = 8 << 20
	minResponseBytes = 1 << 20
	maxResponseBytes = 16 << 20
	maxRequestBytes  = 8 << 20
	requestTimeout   = 5 * time.Second
	assertionSkew    = dreamupdelegation.MaxClockSkew
)

var (
	ErrInvalidRequest   = errors.New("dreamup admin: invalid request")
	ErrAssertionExpired = errors.New("dreamup admin: delegation assertion expired")
	ErrDeadline         = errors.New("dreamup admin: request deadline exceeded")
	ErrRejected         = errors.New("dreamup admin: request rejected")
	ErrUnauthorized     = errors.New("dreamup admin: unauthorized")
	ErrForbidden        = errors.New("dreamup admin: forbidden")
	ErrNotFound         = errors.New("dreamup admin: not found")
	ErrConflict         = errors.New("dreamup admin: conflict")
	ErrRateLimited      = errors.New("dreamup admin: rate limited")
	ErrUnavailable      = errors.New("dreamup admin: unavailable")
	ErrProtocol         = errors.New("dreamup admin: invalid upstream response")
	ErrResponseTooLarge = errors.New("dreamup admin: response too large")
)

var (
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,160}$`)
	requestIDPattern      = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
	strongETagPattern     = regexp.MustCompile(`^"(0|[1-9][0-9]*)"$`)
	opaqueIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,159}$`)
)

// UpstreamError is deliberately body-free. Only the stable classification
// and numeric HTTP status may cross the service boundary.
type UpstreamError struct {
	kind   error
	status int
}

func (e *UpstreamError) Error() string {
	if e == nil {
		return "dreamup admin: upstream failure"
	}
	if e.status != 0 {
		return "dreamup admin: upstream status " + http.StatusText(e.status)
	}
	return e.kind.Error()
}

func (e *UpstreamError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.kind
}

func (e *UpstreamError) StatusCode() int {
	if e == nil {
		return 0
	}
	return e.status
}

// Request describes one exact internal call. The compact assertion must have
// been signed for this method, path, query and encoded body.
type Request struct {
	Method         string
	Path           string
	Query          url.Values
	Body           any
	Assertion      dreamupdelegation.SignedAssertion
	RequestID      string
	IdempotencyKey string
	IfMatch        string
}

type ResponseMeta struct {
	StatusCode int
	RequestID  string
	ETag       string
}

// AssertionRequest is the canonical material an adapter needs to mint a
// request-bound DreamUP administrator assertion.
type AssertionRequest struct {
	Method         string
	PathAndQuery   string
	BodySHA256     string
	EventID        string
	RequestID      string
	IdempotencyKey string
}

type AssertionSource interface {
	Sign(context.Context, AssertionRequest) (dreamupdelegation.SignedAssertion, error)
}

type AssertionSourceFunc func(context.Context, AssertionRequest) (dreamupdelegation.SignedAssertion, error)

func (f AssertionSourceFunc) Sign(ctx context.Context, input AssertionRequest) (dreamupdelegation.SignedAssertion, error) {
	return f(ctx, input)
}

type Client struct {
	base        *url.URL
	http        *http.Client
	assertions  AssertionSource
	now         func() time.Time
	responseMax int64
}

type Option func(*Client)

func WithAssertionSource(source AssertionSource) Option {
	return func(client *Client) { client.assertions = source }
}

func WithClock(now func() time.Time) Option {
	return func(client *Client) {
		if now != nil {
			client.now = now
		}
	}
}

func WithMaxResponseBytes(maximum int64) Option {
	return func(client *Client) { client.responseMax = maximum }
}

// NewClient copies the supplied HTTP client, replaces its redirect policy,
// and bounds its total duration. A nil HTTP client uses a hardened default.
func NewClient(baseURL string, supplied *http.Client, options ...Option) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil || (base.Path != "" && base.Path != "/") || base.RawQuery != "" || base.Fragment != "" {
		return nil, ErrInvalidRequest
	}
	base.Path = strings.TrimRight(base.Path, "/")
	base.RawPath = ""

	if supplied == nil {
		supplied = &http.Client{}
	}
	hardened := *supplied
	hardened.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hardened.Jar = nil
	if hardened.Timeout <= 0 || hardened.Timeout > requestTimeout {
		hardened.Timeout = requestTimeout
	}
	switch transport := hardened.Transport.(type) {
	case nil:
		clone := http.DefaultTransport.(*http.Transport).Clone()
		clone.DisableKeepAlives = true
		hardened.Transport = clone
	case *http.Transport:
		clone := transport.Clone()
		clone.DisableKeepAlives = true
		hardened.Transport = clone
	}

	client := &Client{base: base, http: &hardened, now: func() time.Time { return time.Now().UTC() }, responseMax: MaxResponseBytes}
	for _, option := range options {
		if option != nil {
			option(client)
		}
	}
	if client.now == nil || client.responseMax < minResponseBytes || client.responseMax > maxResponseBytes {
		return nil, ErrInvalidRequest
	}
	return client, nil
}

// Do performs exactly one private HTTP operation. It validates only the
// common JSON envelope; callers with a known DTO must additionally use an
// exact typed decoder (as the typed methods below do).
func (c *Client) Do(ctx context.Context, input Request) (json.RawMessage, ResponseMeta, error) {
	if c == nil || c.base == nil || c.http == nil || c.now == nil || ctx == nil {
		return nil, ResponseMeta{}, ErrInvalidRequest
	}
	if err := validateRequest(input); err != nil {
		return nil, ResponseMeta{}, err
	}
	pathAndQuery, err := dreamupdelegation.CanonicalPathAndQuery(input.Path, input.Query)
	if err != nil {
		return nil, ResponseMeta{}, ErrInvalidRequest
	}
	body, err := encodeRequestBody(input.Body)
	if err != nil {
		return nil, ResponseMeta{}, ErrInvalidRequest
	}
	now := c.now().UTC()
	deadline := now.Add(requestTimeout)
	assertionDeadline := input.Assertion.ExpiresAt.UTC().Add(-assertionSkew)
	if input.Assertion.ExpiresAt.IsZero() || !assertionDeadline.After(now) || (!input.Assertion.NotBefore.IsZero() && input.Assertion.NotBefore.UTC().After(now.Add(assertionSkew))) {
		return nil, ResponseMeta{}, ErrAssertionExpired
	}
	if assertionDeadline.Before(deadline) {
		deadline = assertionDeadline
	}
	requestContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	endpoint := *c.base
	endpoint.Path = strings.TrimRight(c.base.Path, "/") + input.Path
	endpoint.RawPath = ""
	endpoint.RawQuery = ""
	if queryIndex := strings.IndexByte(pathAndQuery, '?'); queryIndex >= 0 {
		endpoint.RawQuery = pathAndQuery[queryIndex+1:]
	}
	var reader io.Reader
	if body != nil {
		reader = &oneShotReader{Reader: bytes.NewReader(body)}
	}
	request, err := http.NewRequestWithContext(requestContext, input.Method, endpoint.String(), reader)
	if err != nil {
		return nil, ResponseMeta{}, ErrInvalidRequest
	}
	request.Close = true
	request.GetBody = nil
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+input.Assertion.Token)
	request.Header.Set("X-Request-ID", input.RequestID)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if input.IdempotencyKey != "" {
		request.Header.Set("Idempotency-Key", input.IdempotencyKey)
	}
	if input.IfMatch != "" {
		request.Header.Set("If-Match", input.IfMatch)
	}

	response, err := c.http.Do(request)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			return nil, ResponseMeta{}, &UpstreamError{kind: ErrDeadline}
		}
		return nil, ResponseMeta{}, &UpstreamError{kind: ErrUnavailable}
	}
	defer response.Body.Close()
	meta := ResponseMeta{StatusCode: response.StatusCode, ETag: response.Header.Get("ETag"), RequestID: input.RequestID}
	if upstreamID := response.Header.Get("X-Request-ID"); upstreamID != "" {
		if upstreamID != input.RequestID {
			return nil, meta, &UpstreamError{kind: ErrProtocol, status: response.StatusCode}
		}
		meta.RequestID = upstreamID
	}
	if response.ContentLength > c.responseMax {
		return nil, meta, &UpstreamError{kind: ErrResponseTooLarge, status: response.StatusCode}
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, c.responseMax+1))
	if err != nil {
		return nil, meta, &UpstreamError{kind: ErrUnavailable, status: response.StatusCode}
	}
	if int64(len(payload)) > c.responseMax {
		return nil, meta, &UpstreamError{kind: ErrResponseTooLarge, status: response.StatusCode}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, meta, classifyStatus(response.StatusCode)
	}
	if !validJSONContentType(response.Header.Get("Content-Type")) {
		return nil, meta, &UpstreamError{kind: ErrProtocol, status: response.StatusCode}
	}
	raw, err := decodeJSONObject(payload)
	if err != nil {
		return nil, meta, &UpstreamError{kind: ErrProtocol, status: response.StatusCode}
	}
	return raw, meta, nil
}

// Execute adapts the application-layer transport port without making that
// layer depend on this HTTP adapter.
func (c *Client) Execute(ctx context.Context, input admincontract.UpstreamRequest) (admincontract.UpstreamResponse, error) {
	var body any
	if len(input.Body) != 0 {
		body = json.RawMessage(append([]byte(nil), input.Body...))
	}
	raw, meta, err := c.Do(ctx, Request{
		Method: input.Method, Path: input.Path, Query: input.Query, Body: body,
		Assertion: input.Assertion, RequestID: input.RequestID, IdempotencyKey: input.IdempotencyKey, IfMatch: input.IfMatch,
	})
	if err != nil {
		return admincontract.UpstreamResponse{}, mapContractError(err)
	}
	return admincontract.UpstreamResponse{StatusCode: meta.StatusCode, Body: raw, RequestID: meta.RequestID, ETag: meta.ETag}, nil
}

type oneShotReader struct{ *bytes.Reader }

func validateRequest(input Request) error {
	if input.Method != http.MethodGet && input.Method != http.MethodPost && input.Method != http.MethodPut && input.Method != http.MethodPatch && input.Method != http.MethodDelete {
		return ErrInvalidRequest
	}
	parsed, err := url.ParseRequestURI(input.Path)
	if err != nil || parsed.IsAbs() || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/internal/v1/") || pathpkg.Clean(parsed.Path) != parsed.Path || parsed.Path != input.Path {
		return ErrInvalidRequest
	}
	if !validRequestID(input.RequestID) || !validBearer(input.Assertion.Token) {
		return ErrInvalidRequest
	}
	if input.Method == http.MethodGet {
		if input.IdempotencyKey != "" && !idempotencyKeyPattern.MatchString(input.IdempotencyKey) {
			return ErrInvalidRequest
		}
	} else if !idempotencyKeyPattern.MatchString(input.IdempotencyKey) {
		return ErrInvalidRequest
	}
	if input.IfMatch != "" && !strongETagPattern.MatchString(input.IfMatch) {
		return ErrInvalidRequest
	}
	return nil
}

func validRequestID(value string) bool {
	return requestIDPattern.MatchString(value)
}

func validBearer(value string) bool {
	if value == "" || len(value) > 16<<10 {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func encodeRequestBody(value any) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > maxRequestBytes {
		return nil, ErrInvalidRequest
	}
	return encoded, nil
}

func validJSONContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "application/json" {
		return false
	}
	for name, value := range parameters {
		if !strings.EqualFold(name, "charset") || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

func decodeJSONObject(payload []byte) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil || len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return nil, ErrProtocol
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrProtocol
	}
	return raw, nil
}

func decodeExact(payload []byte, destination any) error {
	if destination == nil {
		return ErrProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrProtocol
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrProtocol
	}
	return nil
}

func classifyStatus(status int) error {
	kind := ErrProtocol
	switch status {
	case http.StatusBadRequest, http.StatusMethodNotAllowed, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		kind = ErrRejected
	case http.StatusUnauthorized:
		kind = ErrUnauthorized
	case http.StatusForbidden:
		kind = ErrForbidden
	case http.StatusNotFound:
		kind = ErrNotFound
	case http.StatusConflict, http.StatusPreconditionFailed:
		kind = ErrConflict
	case http.StatusTooManyRequests:
		kind = ErrRateLimited
	case http.StatusRequestTimeout:
		// A server-side timeout can happen after the mutation committed, so it
		// must remain receipt-reconciled rather than becoming a terminal 4xx.
		kind = ErrUnavailable
	default:
		if status >= http.StatusBadRequest && status <= 499 {
			kind = ErrRejected
		} else if status >= http.StatusInternalServerError && status <= 599 {
			kind = ErrUnavailable
		}
	}
	return &UpstreamError{kind: kind, status: status}
}

func mapContractError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrRejected):
		return admincontract.ErrInvalidRequest
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrForbidden):
		return admincontract.ErrForbidden
	case errors.Is(err, ErrNotFound):
		return admincontract.ErrNotFound
	case errors.Is(err, ErrConflict):
		return admincontract.ErrConflict
	default:
		return admincontract.ErrUpstream
	}
}

const targetValidationPath = "/internal/v1/identity-access/targets/validate"

type targetValidationRequest struct {
	TargetType string   `json:"targetType"`
	TargetID   string   `json:"targetId"`
	Fields     []string `json:"fields"`
}

type targetValidationResponse struct {
	Target struct {
		TargetType          string `json:"targetType"`
		TargetID            string `json:"targetId"`
		TargetSubjectUserID string `json:"targetSubjectUserId"`
	} `json:"target"`
}

func (c *Client) ValidateIdentityTarget(ctx context.Context, eventID string, target identityaccess.TargetRef, fields []identityaccess.Field) (identityaccess.TargetValidation, error) {
	if c == nil || c.assertions == nil || !validOpaqueValue(eventID, 128) || !validOpaqueValue(target.ID, 256) {
		return identityaccess.TargetValidation{}, identityaccess.ErrInvalidRequest
	}
	targetType, mappedFields, err := mapIdentityTarget(target.Type, fields)
	if err != nil {
		return identityaccess.TargetValidation{}, err
	}
	body, err := json.Marshal(targetValidationRequest{TargetType: targetType, TargetID: target.ID, Fields: mappedFields})
	if err != nil {
		return identityaccess.TargetValidation{}, identityaccess.ErrInvalidRequest
	}
	requestID := requestcontext.ID(ctx)
	if !validRequestID(requestID) {
		return identityaccess.TargetValidation{}, identityaccess.ErrInvalidRequest
	}
	idempotencyKey, err := newInternalIdempotencyKey()
	if err != nil {
		return identityaccess.TargetValidation{}, ErrUnavailable
	}
	assertion, err := c.assertions.Sign(ctx, AssertionRequest{
		Method: http.MethodPost, PathAndQuery: targetValidationPath, BodySHA256: hexDigest(body),
		EventID: eventID, RequestID: requestID, IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return identityaccess.TargetValidation{}, err
	}
	raw, _, err := c.Do(ctx, Request{Method: http.MethodPost, Path: targetValidationPath, Body: json.RawMessage(body), Assertion: assertion, RequestID: requestID, IdempotencyKey: idempotencyKey})
	if err != nil {
		return identityaccess.TargetValidation{}, mapIdentityAccessError(err)
	}
	var response targetValidationResponse
	if err := decodeExact(raw, &response); err != nil {
		return identityaccess.TargetValidation{}, &UpstreamError{kind: ErrProtocol, status: http.StatusOK}
	}
	if response.Target.TargetType != targetType || response.Target.TargetID != target.ID || !validOpaqueValue(response.Target.TargetSubjectUserID, 256) {
		return identityaccess.TargetValidation{}, &UpstreamError{kind: ErrProtocol, status: http.StatusOK}
	}
	return identityaccess.TargetValidation{Target: target, SubjectUserID: identity.UserID(response.Target.TargetSubjectUserID)}, nil
}

func mapIdentityTarget(targetType identityaccess.TargetType, fields []identityaccess.Field) (string, []string, error) {
	mappedType := ""
	switch targetType {
	case identityaccess.TargetApplication:
		mappedType = "application"
	case identityaccess.TargetCheckIn:
		mappedType = "participant"
	default:
		return "", nil, identityaccess.ErrInvalidRequest
	}
	if len(fields) == 0 {
		return "", nil, identityaccess.ErrInvalidRequest
	}
	mapping := map[identityaccess.Field]string{
		identityaccess.FieldLegalName:      "legal_name",
		identityaccess.FieldIdentityNumber: "identity_document_number",
		identityaccess.FieldIdentityPhoto:  "portrait",
		identityaccess.FieldContactEmail:   "email",
		identityaccess.FieldContactMobile:  "mobile",
	}
	result := make([]string, 0, len(fields))
	seen := make(map[identityaccess.Field]struct{}, len(fields))
	for _, field := range fields {
		mapped, ok := mapping[field]
		if !ok {
			return "", nil, identityaccess.ErrInvalidRequest
		}
		if _, duplicate := seen[field]; duplicate {
			return "", nil, identityaccess.ErrInvalidRequest
		}
		seen[field] = struct{}{}
		result = append(result, mapped)
	}
	return mappedType, result, nil
}

func mapIdentityAccessError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return identityaccess.ErrNotFound
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrForbidden):
		return identityaccess.ErrForbidden
	case errors.Is(err, ErrConflict):
		return identityaccess.ErrConflict
	default:
		return err
	}
}

type OperationReceipt struct {
	Action        string    `json:"action"`
	TargetType    string    `json:"target_type"`
	TargetID      string    `json:"target_id"`
	Outcome       string    `json:"outcome"`
	ResultVersion int64     `json:"result_version"`
	ReceiptHash   string    `json:"receipt_hash"`
	RequestID     string    `json:"request_id"`
	CreatedAt     time.Time `json:"created_at"`
}

type operationReceiptResponse struct {
	Receipt OperationReceipt `json:"receipt"`
}

// LookupOperationReceipt is the sole read-only recovery call for an operation
// whose mutation response may have been lost. It never replays the mutation.
func (c *Client) LookupOperationReceipt(ctx context.Context, eventID, operationRequestID, requestID, idempotencyKey string, assertion dreamupdelegation.SignedAssertion) (OperationReceipt, error) {
	if !opaqueIDPattern.MatchString(eventID) || !opaqueIDPattern.MatchString(operationRequestID) || !idempotencyKeyPattern.MatchString(idempotencyKey) {
		return OperationReceipt{}, ErrInvalidRequest
	}
	raw, _, err := c.Do(ctx, Request{
		Method: http.MethodGet, Path: "/internal/v1/events/" + eventID + "/operation-receipts/" + operationRequestID,
		Assertion: assertion, RequestID: requestID, IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return OperationReceipt{}, err
	}
	var response operationReceiptResponse
	if err := decodeExact(raw, &response); err != nil {
		return OperationReceipt{}, &UpstreamError{kind: ErrProtocol, status: http.StatusOK}
	}
	receipt := response.Receipt
	if receipt.Action == "" || receipt.TargetType == "" || receipt.TargetID == "" || receipt.Outcome == "" || receipt.ResultVersion <= 0 || receipt.ReceiptHash == "" || !validRequestID(receipt.RequestID) || receipt.CreatedAt.IsZero() {
		return OperationReceipt{}, &UpstreamError{kind: ErrProtocol, status: http.StatusOK}
	}
	return receipt, nil
}

func validOpaqueValue(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return false
		}
	}
	return true
}

func hexDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func newInternalIdempotencyKey() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

var _ identityaccess.TargetValidator = (*Client)(nil)
var _ admincontract.UpstreamClient = (*Client)(nil)
