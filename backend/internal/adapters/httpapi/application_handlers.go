package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
)

// ReauthVerifier validates and consumes one-time reauthentication tokens for
// high-risk operations (ADR-0004 §6.7). A nil verifier fails closed: the
// operation is denied until the reauthentication contract is implemented.
type ReauthVerifier interface {
	// VerifyAndConsume checks the token for the given action, session and
	// resource. A consumed token can never be reused.
	VerifyAndConsume(ctx context.Context, token, action, sessionID string, appID applications.ApplicationID, clientID applications.OAuthClientID) error
}

// RotationRateChecker abstracts the secret rotation rate limiter (ADR-0004
// §6). The Redis rate limiter satisfies this interface; a nil checker fails
// closed.
type RotationRateChecker interface {
	CheckRotation(ctx context.Context, ip, clientIDHash string, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
}

// ApplicationHandlers serves the OAuth application management plane
// (ADR-0004 §7). All routes require a valid session and CSRF token; these
// are enforced by middleware, not here.
type ApplicationHandlers struct {
	svc            *applications.Service
	permResolver   permissions.Resolver
	reauth         ReauthVerifier
	rotationRates  RotationRateChecker
	rotationLimit  int
	rotationWindow time.Duration
	logger         *slog.Logger
}

// NewApplicationHandlers builds the application management handlers. reauth
// and rotationRates may be nil while their infrastructure is unavailable;
// high-risk operations then fail closed.
func NewApplicationHandlers(
	svc *applications.Service,
	permResolver permissions.Resolver,
	reauth ReauthVerifier,
	rotationRates RotationRateChecker,
	rotationLimit int,
	rotationWindow time.Duration,
	logger *slog.Logger,
) *ApplicationHandlers {
	return &ApplicationHandlers{
		svc:            svc,
		permResolver:   permResolver,
		reauth:         reauth,
		rotationRates:  rotationRates,
		rotationLimit:  rotationLimit,
		rotationWindow: rotationWindow,
		logger:         logger,
	}
}

// checkCapability resolves the caller's capabilities fail-closed and returns
// the actor when the required capability is granted. Capability resolution
// errors deny the operation with a 500 (never a silent grant). Denied
// management attempts with a non-empty eventType are recorded as denied
// audit events.
func (h *ApplicationHandlers) checkCapability(
	w http.ResponseWriter,
	r *http.Request,
	manage bool,
	eventType, operation string,
	appID applications.ApplicationID,
) (identity.UserID, bool) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return "", false
	}
	caps, err := h.permResolver.Resolve(r.Context(), principal.UserID)
	if err != nil {
		WriteInternalError(w, r)
		return "", false
	}
	granted := caps.ApplicationRead
	if manage {
		granted = caps.ApplicationManage
	}
	if !granted {
		if eventType != "" {
			h.svc.RecordEvent(r.Context(), eventType, principal.UserID, appID, "",
				request.ID(r.Context()), operation, applications.SecurityEventDenied, "authorization")
		}
		WriteForbidden(w, r)
		return "", false
	}
	return principal.UserID, true
}

// applicationIDFromPath reads and shape-checks the applicationId path
// parameter. Malformed IDs yield ok=false; callers respond 404 so resource
// existence is never revealed (anti-enumeration).
func applicationIDFromPath(r *http.Request) (applications.ApplicationID, bool) {
	raw := chi.URLParam(r, "applicationId")
	if !applications.HasApplicationIDPrefix(raw) {
		return "", false
	}
	return applications.ApplicationID(raw), true
}

// ---- Create with initial client ----

type applicationCreateInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Audience    string `json:"audience"`
	OwnerID     string `json:"ownerId"`
}

type clientCreateInput struct {
	Name          string   `json:"name"`
	Profile       string   `json:"profile"`
	RedirectURIs  []string `json:"redirectUris"`
	LogoutURI     string   `json:"logoutUri"`
	AllowedScopes []string `json:"allowedScopes"`
	ConsentMode   string   `json:"consentMode"`
}

type applicationWithInitialClientRequest struct {
	Application   applicationCreateInput `json:"application"`
	InitialClient clientCreateInput      `json:"initialClient"`
}

type applicationWithInitialClientResponse struct {
	ApplicationID string `json:"applicationId"`
	ClientID      string `json:"clientId"`
	// ClientSecret is present exactly once for confidential clients and is
	// never persisted; omitempty keeps it absent for public clients.
	ClientSecret string `json:"clientSecret,omitempty"`
}

// CreateWithInitialClient handles POST /api/v1/admin/applications/with-initial-client.
func (h *ApplicationHandlers) CreateWithInitialClient(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.checkCapability(w, r, true,
		applications.EventApplicationCreated, "application.create", "")
	if !ok {
		return
	}

	var req applicationWithInitialClientRequest
	if err := decodeJSONBody(w, r, &req, "create application"); err != nil {
		return
	}

	appIn := applications.ApplicationInput{
		Name:        req.Application.Name,
		Description: req.Application.Description,
		Audience:    applications.ApplicationAudience(req.Application.Audience),
		OwnerID:     req.Application.OwnerID,
	}
	clientIn := applications.ClientInput{
		Name:         req.InitialClient.Name,
		Profile:      applications.ClientProfile(req.InitialClient.Profile),
		RedirectURIs: req.InitialClient.RedirectURIs,
		LogoutURI:    req.InitialClient.LogoutURI,
		Scopes:       req.InitialClient.AllowedScopes,
		ConsentMode:  applications.ConsentMode(req.InitialClient.ConsentMode),
	}
	// Both halves are validated before responding so a single request
	// reports every field error at once.
	var fieldErrors []FieldError
	if err := applications.ValidateApplicationInput(appIn); err != nil {
		fieldErrors = append(fieldErrors, prefixFieldErrors(err, "application.")...)
	}
	if err := applications.ValidateClientInput(clientIn); err != nil {
		fieldErrors = append(fieldErrors, prefixFieldErrors(err, "initialClient.")...)
	}
	if len(fieldErrors) > 0 {
		WriteValidation(w, r, "请求参数校验失败。", fieldErrors)
		return
	}

	result, err := h.svc.CreateWithInitialClient(r.Context(), actor, request.ID(r.Context()), appIn, clientIn)
	if err != nil {
		switch {
		case errors.Is(err, applications.ErrOwnerNotFound):
			WriteValidation(w, r, "请求参数校验失败。", []FieldError{
				{Field: "application.ownerId", Message: "负责人不存在或已停用。"},
			})
		case errors.Is(err, applications.ErrDuplicateName):
			writeError(w, r, http.StatusConflict, CodeConflict, "应用名称已存在。", nil)
		case errors.Is(err, applications.ErrProviderConflict):
			writeError(w, r, http.StatusConflict, CodeConflict, "身份提供方报告冲突，请稍后重试。", nil)
		case errors.Is(err, applications.ErrProviderUnavailable):
			WriteProviderUnavailable(w, r)
		default:
			WriteInternalError(w, r)
		}
		return
	}

	writeJSONNoStore(w, r, http.StatusCreated, applicationWithInitialClientResponse{
		ApplicationID: string(result.ApplicationID),
		ClientID:      string(result.ClientID),
		ClientSecret:  result.ClientSecret,
	})
}

// ---- List ----

var validApplicationSorts = map[string]struct{}{
	"updatedAt": {}, "-updatedAt": {},
	"createdAt": {}, "-createdAt": {},
	"name": {}, "-name": {},
}

type applicationListItem struct {
	ApplicationID string    `json:"applicationId"`
	Name          string    `json:"name"`
	Audience      string    `json:"audience"`
	OwnerID       string    `json:"ownerId"`
	OwnerName     string    `json:"ownerName"`
	Status        string    `json:"status"`
	ClientCount   int       `json:"clientCount"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type applicationListPage struct {
	NextCursor *string `json:"nextCursor"`
	HasMore    bool    `json:"hasMore"`
}

type applicationListResponse struct {
	Items []applicationListItem `json:"items"`
	Page  applicationListPage   `json:"page"`
}

// ListApplications handles GET /api/v1/admin/applications.
func (h *ApplicationHandlers) ListApplications(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.checkCapability(w, r, false, "", "application.list", ""); !ok {
		return
	}

	q := r.URL.Query()
	query := applications.ListQuery{
		Cursor:  q.Get("cursor"),
		Query:   q.Get("query"),
		Sort:    q.Get("sort"),
		Status:  q.Get("status"),
		OwnerID: q.Get("ownerId"),
	}

	if raw := q.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			WriteBadRequest(w, r, "limit 参数必须为 1 至 100 的整数。")
			return
		}
		query.Limit = limit
	}
	if query.Sort != "" {
		if _, ok := validApplicationSorts[query.Sort]; !ok {
			WriteBadRequest(w, r, "sort 参数无效。")
			return
		}
	}
	switch query.Status {
	case "", string(applications.StatusActive), string(applications.StatusDisabled):
	default:
		WriteBadRequest(w, r, "status 参数无效。")
		return
	}
	query.Audience = q.Get("audience")
	switch query.Audience {
	case "", string(applications.AudienceInternal), string(applications.AudienceExternal), string(applications.AudienceHybrid):
	default:
		WriteBadRequest(w, r, "audience 参数无效。")
		return
	}

	result, err := h.svc.List(r.Context(), query)
	if err != nil {
		if errors.Is(err, applications.ErrInvalidCursor) {
			WriteBadRequest(w, r, "分页游标无效。")
			return
		}
		WriteInternalError(w, r)
		return
	}

	items := make([]applicationListItem, len(result.Items))
	for i, s := range result.Items {
		items[i] = applicationListItem{
			ApplicationID: string(s.ID),
			Name:          s.Name,
			Audience:      string(s.Audience),
			OwnerID:       string(s.OwnerID),
			OwnerName:     s.OwnerName,
			Status:        string(s.Status),
			ClientCount:   s.ClientCount,
			UpdatedAt:     s.UpdatedAt.UTC(),
		}
	}
	page := applicationListPage{HasMore: result.HasMore}
	if result.NextCursor != "" {
		cursor := result.NextCursor
		page.NextCursor = &cursor
	}
	writeJSONNoStore(w, r, http.StatusOK, applicationListResponse{Items: items, Page: page})
}

// ---- Detail / Patch / Enable / Disable / Delete ----

type redirectURIResponse struct {
	URI        string    `json:"uri"`
	IsLoopback bool      `json:"isLoopback"`
	AddedAt    time.Time `json:"addedAt"`
}

type scopeResponse struct {
	Scope       string `json:"scope"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

type clientSecretResponse struct {
	SecretID      string     `json:"secretId"`
	Label         string     `json:"label"`
	CreatedAt     time.Time  `json:"createdAt"`
	LastRotatedAt *time.Time `json:"lastRotatedAt"`
}

type clientResponse struct {
	ClientID                string                 `json:"clientId"`
	ApplicationID           string                 `json:"applicationId"`
	Name                    string                 `json:"name"`
	ClientType              string                 `json:"clientType"`
	GrantTypes              []string               `json:"grantTypes"`
	TokenEndpointAuthMethod string                 `json:"tokenEndpointAuthMethod"`
	RedirectURIs            []redirectURIResponse  `json:"redirectUris"`
	LogoutURI               *string                `json:"logoutUri"`
	AllowedScopes           []scopeResponse        `json:"allowedScopes"`
	ConsentMode             string                 `json:"consentMode"`
	Status                  string                 `json:"status"`
	ClientSecrets           []clientSecretResponse `json:"clientSecrets"`
	CreatedAt               time.Time              `json:"createdAt"`
	UpdatedAt               time.Time              `json:"updatedAt"`
}

type auditEntryResponse struct {
	EventID    string    `json:"eventId"`
	EventType  string    `json:"eventType"`
	ActorName  string    `json:"actorName"`
	OccurredAt time.Time `json:"occurredAt"`
	Result     string    `json:"result"`
}

type applicationDetailResponse struct {
	ApplicationID string               `json:"applicationId"`
	Name          string               `json:"name"`
	Description   string               `json:"description"`
	LogoURL       *string              `json:"logoUrl"`
	Audience      string               `json:"audience"`
	OwnerID       string               `json:"ownerId"`
	OwnerName     string               `json:"ownerName"`
	Status        string               `json:"status"`
	Clients       []clientResponse     `json:"clients"`
	Grants        []any                `json:"grants"`
	AuditEntries  []auditEntryResponse `json:"auditEntries"`
	CreatedAt     time.Time            `json:"createdAt"`
	UpdatedAt     time.Time            `json:"updatedAt"`
}

// GetApplication handles GET /api/v1/admin/applications/{applicationId}.
func (h *ApplicationHandlers) GetApplication(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.checkCapability(w, r, false, "", "application.read", ""); !ok {
		return
	}
	appID, ok := applicationIDFromPath(r)
	if !ok {
		WriteNotFound(w, r)
		return
	}

	detail, err := h.svc.Get(r.Context(), appID)
	if err != nil {
		writeApplicationLookupError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, applicationDetailJSON(detail))
}

type applicationUpdateRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Audience    *string `json:"audience"`
	OwnerID     *string `json:"ownerId"`
}

// UpdateApplication handles PATCH /api/v1/admin/applications/{applicationId}.
func (h *ApplicationHandlers) UpdateApplication(w http.ResponseWriter, r *http.Request) {
	appID, actor, ok := h.manageFromPath(w, r, applications.EventApplicationUpdated, "application.update")
	if !ok {
		return
	}

	var req applicationUpdateRequest
	if err := decodeJSONBody(w, r, &req, "update application"); err != nil {
		return
	}
	if req.Name == nil && req.Description == nil && req.Audience == nil && req.OwnerID == nil {
		WriteBadRequest(w, r, "至少需要提交一个更新字段。")
		return
	}

	patch := applications.ApplicationPatch{
		Name:        req.Name,
		Description: req.Description,
	}
	if req.Audience != nil {
		audience := applications.ApplicationAudience(*req.Audience)
		if !audience.IsValid() {
			WriteValidation(w, r, "请求参数校验失败。", []FieldError{
				{Field: "audience", Message: "未知的应用受众类型。"},
			})
			return
		}
		patch.Audience = &audience
	}
	if req.OwnerID != nil {
		ownerID := identity.UserID(*req.OwnerID)
		patch.OwnerID = &ownerID
	}

	if _, err := h.svc.UpdateApplication(r.Context(), actor, appID, request.ID(r.Context()), patch); err != nil {
		h.writeMutationError(w, r, err, nil, "应用名称已存在。")
		return
	}

	detail, err := h.svc.Get(r.Context(), appID)
	if err != nil {
		writeApplicationLookupError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, applicationDetailJSON(detail))
}

// EnableApplication handles POST /api/v1/admin/applications/{applicationId}/enable.
func (h *ApplicationHandlers) EnableApplication(w http.ResponseWriter, r *http.Request) {
	h.setApplicationStatus(w, r, true)
}

// DisableApplication handles POST /api/v1/admin/applications/{applicationId}/disable.
func (h *ApplicationHandlers) DisableApplication(w http.ResponseWriter, r *http.Request) {
	h.setApplicationStatus(w, r, false)
}

func (h *ApplicationHandlers) setApplicationStatus(w http.ResponseWriter, r *http.Request, enable bool) {
	eventType := applications.EventApplicationDisabled
	operation := "application.disable"
	if enable {
		eventType = applications.EventApplicationEnabled
		operation = "application.enable"
	}
	appID, actor, ok := h.manageFromPath(w, r, eventType, operation)
	if !ok {
		return
	}

	if err := h.svc.SetStatus(r.Context(), actor, appID, request.ID(r.Context()), enable); err != nil {
		h.writeMutationError(w, r, err, nil, "应用名称已存在。")
		return
	}

	detail, err := h.svc.Get(r.Context(), appID)
	if err != nil {
		writeApplicationLookupError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, applicationDetailJSON(detail))
}

// DeleteApplication handles DELETE /api/v1/admin/applications/{applicationId}.
// Deleting an application is a high-risk operation and requires a fresh
// reauthentication token (ADR-0004 §6.7).
func (h *ApplicationHandlers) DeleteApplication(w http.ResponseWriter, r *http.Request) {
	appID, actor, ok := h.manageFromPath(w, r, applications.EventApplicationDeleted, "application.delete")
	if !ok {
		return
	}

	if !h.verifyReauthentication(w, r, actor, applications.EventApplicationDeleted, "application.delete", appID, "") {
		return
	}

	if err := h.svc.Delete(r.Context(), actor, appID, request.ID(r.Context())); err != nil {
		h.writeMutationError(w, r, err, nil, "应用名称已存在。")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// verifyReauthentication enforces the reauthentication requirement for
// high-risk operations. It fails closed: without a verifier implementation,
// an absent token or any verification failure denies the operation. Grants
// are bound to the caller's session, so a stolen token cannot be redeemed
// from another session.
func (h *ApplicationHandlers) verifyReauthentication(w http.ResponseWriter, r *http.Request, actor identity.UserID, eventType, action string, appID applications.ApplicationID, clientID applications.OAuthClientID) bool {
	token := r.Header.Get("X-Reauthentication-Token")
	principal, hasPrincipal := PrincipalFromContext(r.Context())
	var err error
	if h.reauth == nil || token == "" || !hasPrincipal {
		err = errors.New("reauthentication unavailable")
	} else {
		err = h.reauth.VerifyAndConsume(r.Context(), token, action, string(principal.SessionID), appID, clientID)
	}
	if err != nil {
		h.svc.RecordEvent(r.Context(), eventType, actor, appID, clientID,
			request.ID(r.Context()), action, applications.SecurityEventDenied, "reauthentication")
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	return true
}

// manageFromPath combines the manage-capability check with the path
// application ID extraction shared by all mutating endpoints.
func (h *ApplicationHandlers) manageFromPath(w http.ResponseWriter, r *http.Request, eventType, operation string) (applications.ApplicationID, identity.UserID, bool) {
	appID, ok := applicationIDFromPath(r)
	if !ok {
		// Shape-invalid IDs are answered 404 without touching capabilities or
		// audit, exactly like a missing resource (anti-enumeration).
		WriteNotFound(w, r)
		return "", "", false
	}
	actor, granted := h.checkCapability(w, r, true, eventType, operation, appID)
	if !granted {
		return "", "", false
	}
	return appID, actor, true
}

// writeMutationError maps use-case errors of mutating endpoints onto the
// frozen error contract. extraFieldErrors allows callers to append
// endpoint-specific field errors for validation failures; duplicateMessage
// is the resource-specific unique-name conflict message.
func (h *ApplicationHandlers) writeMutationError(w http.ResponseWriter, r *http.Request, err error, extraFieldErrors []FieldError, duplicateMessage string) {
	switch {
	case errors.Is(err, applications.ErrNotFound):
		WriteNotFound(w, r)
	case errors.Is(err, applications.ErrOwnerNotFound):
		fieldErrors := append(extraFieldErrors, FieldError{Field: "ownerId", Message: "负责人不存在或已停用。"})
		WriteValidation(w, r, "请求参数校验失败。", fieldErrors)
	case isValidationErrors(err):
		WriteValidation(w, r, "请求参数校验失败。", prefixFieldErrors(err, ""))
	case errors.Is(err, applications.ErrDuplicateName):
		writeError(w, r, http.StatusConflict, CodeConflict, duplicateMessage, nil)
	case errors.Is(err, applications.ErrInvalidStateTransition), errors.Is(err, applications.ErrConflict):
		writeError(w, r, http.StatusConflict, CodeConflict, "资源当前状态不允许该操作。", nil)
	case errors.Is(err, applications.ErrProviderConflict):
		writeError(w, r, http.StatusConflict, CodeConflict, "身份提供方报告冲突，请稍后重试。", nil)
	case errors.Is(err, applications.ErrProviderUnavailable):
		WriteProviderUnavailable(w, r)
	default:
		WriteInternalError(w, r)
	}
}

// writeApplicationLookupError maps read-path lookup failures. Anything that
// is not found is answered with the same 404 (anti-enumeration).
func writeApplicationLookupError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, applications.ErrNotFound) {
		WriteNotFound(w, r)
		return
	}
	WriteInternalError(w, r)
}

// isValidationErrors reports whether err is a domain validation failure.
func isValidationErrors(err error) bool {
	var ve *applications.ValidationErrors
	return errors.As(err, &ve)
}

// prefixFieldErrors converts domain field errors into HTTP field errors,
// prefixing every field path (e.g. "application." or "initialClient.").
func prefixFieldErrors(err error, prefix string) []FieldError {
	var ve *applications.ValidationErrors
	if !errors.As(err, &ve) {
		return nil
	}
	out := make([]FieldError, len(ve.Errors))
	for i, fe := range ve.Errors {
		out[i] = FieldError{Field: prefix + fe.Field, Message: fe.Message}
	}
	return out
}

// ---- Response rendering ----

func applicationDetailJSON(d applications.Detail) applicationDetailResponse {
	clients := make([]clientResponse, len(d.Clients))
	for i, c := range d.Clients {
		clients[i] = clientJSON(c)
	}
	audits := make([]auditEntryResponse, len(d.AuditEntries))
	for i, e := range d.AuditEntries {
		audits[i] = auditEntryResponse{
			EventID:    string(e.EventID),
			EventType:  e.EventType,
			ActorName:  e.ActorName,
			OccurredAt: e.OccurredAt.UTC(),
			Result:     string(e.Result),
		}
	}
	return applicationDetailResponse{
		ApplicationID: string(d.ID),
		Name:          d.Name,
		Description:   d.Description,
		LogoURL:       nullableString(d.LogoURL),
		Audience:      string(d.Audience),
		OwnerID:       string(d.OwnerID),
		OwnerName:     d.OwnerName,
		Status:        string(d.Status),
		Clients:       clients,
		Grants:        []any{},
		AuditEntries:  audits,
		CreatedAt:     d.CreatedAt.UTC(),
		UpdatedAt:     d.UpdatedAt.UTC(),
	}
}

func clientJSON(c applications.OAuthClient) clientResponse {
	grantTypes := []string{}
	if rules, ok := c.Profile.Rules(); ok {
		grantTypes = make([]string, len(rules.GrantTypes))
		for i, gt := range rules.GrantTypes {
			grantTypes[i] = string(gt)
		}
	}
	uris := make([]redirectURIResponse, len(c.RedirectURIs))
	for i, u := range c.RedirectURIs {
		uris[i] = redirectURIResponse{URI: u.URI, IsLoopback: u.IsLoopback, AddedAt: u.AddedAt.UTC()}
	}
	scopes := make([]scopeResponse, 0, len(c.Scopes))
	for _, s := range c.Scopes {
		for _, def := range applications.ScopeCatalog {
			if def.Scope == s {
				scopes = append(scopes, scopeResponse{
					Scope:       def.Scope,
					Label:       def.Label,
					Description: def.Description,
					Required:    def.Required,
				})
				break
			}
		}
	}
	secrets := make([]clientSecretResponse, len(c.SecretRecords))
	for i, s := range c.SecretRecords {
		var rotated *time.Time
		if s.LastRotatedAt != nil {
			t := s.LastRotatedAt.UTC()
			rotated = &t
		}
		secrets[i] = clientSecretResponse{
			SecretID:      string(s.ID),
			Label:         s.Label,
			CreatedAt:     s.CreatedAt.UTC(),
			LastRotatedAt: rotated,
		}
	}
	return clientResponse{
		ClientID:                string(c.ID),
		ApplicationID:           string(c.ApplicationID),
		Name:                    c.Name,
		ClientType:              string(c.ClientType),
		GrantTypes:              grantTypes,
		TokenEndpointAuthMethod: string(c.TokenEndpointAuth),
		RedirectURIs:            uris,
		LogoutURI:               nullableString(c.LogoutURI),
		AllowedScopes:           scopes,
		ConsentMode:             string(c.ConsentMode),
		Status:                  string(c.Status),
		ClientSecrets:           secrets,
		CreatedAt:               c.CreatedAt.UTC(),
		UpdatedAt:               c.UpdatedAt.UTC(),
	}
}

// writeJSONNoStore writes a JSON success response with Cache-Control:
// no-store — mandatory wherever secret material may appear, and harmless
// elsewhere on the management plane. The request ID header keeps success
// responses correlated with logs and audit rows, like error responses.
func writeJSONNoStore(w http.ResponseWriter, r *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Request-ID", request.ID(r.Context()))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
