package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/mscaccess"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

const maxMSCWriteBodyBytes = 4 * 1024

type MSCWorkforceWriter interface {
	ChangeUserStatus(ctx context.Context, mutation workforce.UserStatusMutation) (bool, error)
	RevokeUserSessions(ctx context.Context, actor, userID identity.UserID, requestID string) error
	LinkEmployee(ctx context.Context, actor identity.UserID, input workforce.EmployeeProfileInput, requestID string) (workforce.EmployeeProfile, error)
	UpdateEmployee(ctx context.Context, actor identity.UserID, input workforce.EmployeeProfileInput, requestID string) (workforce.EmployeeProfile, error)
	OffboardEmployee(ctx context.Context, actor, userID identity.UserID, requestID string) (workforce.OffboardingResult, error)
	CreateDepartment(ctx context.Context, actor identity.UserID, input workforce.DepartmentInput, requestID string) (workforce.DepartmentDetail, error)
	UpdateDepartment(ctx context.Context, actor identity.UserID, departmentID workforce.DepartmentID, patch workforce.DepartmentPatch, requestID string) (workforce.DepartmentDetail, error)
	DeleteDepartment(ctx context.Context, actor identity.UserID, departmentID workforce.DepartmentID, requestID string) error
}

type MSCWriteHandlers struct {
	verifier    *mscaccess.Verifier
	workforce   MSCWorkforceWriter
	actorUserID identity.UserID
	logger      *slog.Logger
}

func NewMSCWriteHandlers(verifier *mscaccess.Verifier, writer MSCWorkforceWriter,
	actorUserID identity.UserID, logger *slog.Logger,
) *MSCWriteHandlers {
	return &MSCWriteHandlers{verifier: verifier, workforce: writer, actorUserID: actorUserID, logger: logger}
}

func (h *MSCWriteHandlers) ready() bool {
	return h.verifier != nil && h.workforce != nil && h.actorUserID != ""
}

func (h *MSCWriteHandlers) authorize(w http.ResponseWriter, r *http.Request, capability string, body []byte) (string, bool) {
	actor, err := h.verifier.Verify(r, capability, body)
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "未授权。", nil)
		return "", false
	}
	return actor, true
}

type mscUserStatusRequest struct {
	Status string `json:"status"`
}

type mscUserStatusResponse struct {
	UserID                string `json:"userId"`
	Status                string `json:"status"`
	SessionCleanupPending bool   `json:"sessionCleanupPending"`
}

func (h *MSCWriteHandlers) UpdateUserStatus(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		WriteNotFound(w, r)
		return
	}
	body, ok := readMSCWriteBody(w, r)
	if !ok {
		return
	}
	actor, ok := h.authorize(w, r, mscaccess.CapabilityUserWrite, body)
	if !ok {
		return
	}
	userID, valid := managedUserID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	payload, ok := decodeMSCWritePayload[mscUserStatusRequest](w, r, body)
	if !ok {
		return
	}
	status := identity.UserStatus(payload.Status)
	if !status.IsValid() || status == identity.UserStatusPending {
		WriteBadRequest(w, r, "状态值不受支持。")
		return
	}
	pending, err := h.workforce.ChangeUserStatus(r.Context(), workforce.UserStatusMutation{
		ActorUserID:    h.actorUserID,
		ActorLabel:     actor,
		TargetUserID:   userID,
		Status:         status,
		RevokeSessions: status == identity.UserStatusDisabled,
		RequestID:      request.ID(r.Context()),
	})
	if err != nil {
		h.writeMSCWorkforceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, mscUserStatusResponse{
		UserID: string(userID), Status: string(status), SessionCleanupPending: pending,
	})
}

func (h *MSCWriteHandlers) writeMSCWorkforceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, workforce.ErrInvalidCursor):
		WriteBadRequest(w, r, "游标无效或与当前筛选条件不匹配。")
	case errors.Is(err, workforce.ErrInvalidInput):
		WriteBadRequest(w, r, "状态变更请求无效。")
	case errors.Is(err, workforce.ErrNotFound):
		WriteNotFound(w, r)
	case errors.Is(err, workforce.ErrConflict):
		writeError(w, r, http.StatusConflict, CodeConflict, "该账号仍有待处理的会话清理任务。", nil)
	case errors.Is(err, workforce.ErrDepartmentCycle):
		writeError(w, r, http.StatusConflict, CodeConflict, "部门层级不能形成循环。", nil)
	case errors.Is(err, workforce.ErrDepartmentNotEmpty):
		writeError(w, r, http.StatusConflict, CodeConflict, "仅可删除没有成员和子部门的空部门。", nil)
	case errors.Is(err, workforce.ErrEmployeeNotActive):
		writeError(w, r, http.StatusConflict, CodeConflict, "员工已进入离职流程，不能继续修改。", nil)
	case errors.Is(err, workforce.ErrSupervisorNotActive):
		WriteBadRequest(w, r, "主管或负责人必须是有效在职员工。")
	case errors.Is(err, workforce.ErrUserNotActive):
		WriteBadRequest(w, r, "仅可为有效用户关联员工档案。")
	default:
		if h.logger != nil {
			h.logger.Error("msc workforce mutation failed",
				"requestId", request.ID(r.Context()),
				"errorClass", observability.ClassifyError(err),
				"errorDetail", observability.RedactedError(err, 256))
		}
		WriteInternalError(w, r)
	}
}

func readMSCWriteBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	limited := io.LimitReader(r.Body, maxMSCWriteBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		WriteBadRequest(w, r, "请求体读取失败。")
		return nil, false
	}
	if len(body) > maxMSCWriteBodyBytes {
		WriteRequestBodyTooLarge(w, r)
		return nil, false
	}
	return body, true
}

func decodeMSCWritePayload[T any](w http.ResponseWriter, r *http.Request, raw []byte) (T, bool) {
	var payload T
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		WriteBadRequest(w, r, "请求体格式不正确。")
		var zero T
		return zero, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		WriteBadRequest(w, r, "请求体格式不正确。")
		var zero T
		return zero, false
	}
	return payload, true
}
