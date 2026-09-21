package httpapi

import (
	"net/http"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/mscaccess"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

type mscEmployeeProfileRequest struct {
	UserID           string `json:"userId"`
	DepartmentID     string `json:"departmentId"`
	Title            string `json:"title"`
	SupervisorUserID string `json:"supervisorUserId"`
}

type mscDepartmentMutationRequest struct {
	Name               string `json:"name"`
	ParentDepartmentID string `json:"parentDepartmentId"`
	OwnerUserID        string `json:"ownerUserId"`
}

type mscDepartmentPatchRequest struct {
	Name               *string                `json:"name"`
	ParentDepartmentID optionalNullableString `json:"parentDepartmentId"`
	OwnerUserID        optionalNullableString `json:"ownerUserId"`
}

func (h *MSCWriteHandlers) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		WriteNotFound(w, r)
		return
	}
	body, ok := readMSCWriteBody(w, r)
	if !ok {
		return
	}
	if _, ok := h.authorize(w, r, mscaccess.CapabilityUserWrite, body); !ok {
		return
	}
	userID, valid := managedUserID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	if err := h.workforce.RevokeUserSessions(r.Context(), h.actorUserID, userID, request.ID(r.Context())); err != nil {
		h.writeMSCWorkforceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *MSCWriteHandlers) LinkEmployee(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		WriteNotFound(w, r)
		return
	}
	body, ok := readMSCWriteBody(w, r)
	if !ok {
		return
	}
	if _, ok := h.authorize(w, r, mscaccess.CapabilityEmployeeWrite, body); !ok {
		return
	}
	payload, ok := decodeMSCWritePayload[mscEmployeeProfileRequest](w, r, body)
	if !ok {
		return
	}
	profile, err := h.workforce.LinkEmployee(r.Context(), h.actorUserID, workforce.EmployeeProfileInput{
		UserID:           identity.UserID(payload.UserID),
		DepartmentID:     workforce.DepartmentID(payload.DepartmentID),
		Title:            payload.Title,
		SupervisorUserID: identity.UserID(payload.SupervisorUserID),
	}, request.ID(r.Context()))
	if err != nil {
		h.writeMSCWorkforceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusCreated, toEmployeeMutationResponse(profile))
}

func (h *MSCWriteHandlers) UpdateEmployee(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		WriteNotFound(w, r)
		return
	}
	body, ok := readMSCWriteBody(w, r)
	if !ok {
		return
	}
	if _, ok := h.authorize(w, r, mscaccess.CapabilityEmployeeWrite, body); !ok {
		return
	}
	userID, valid := managedUserID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	payload, ok := decodeMSCWritePayload[mscEmployeeProfileRequest](w, r, body)
	if !ok {
		return
	}
	profile, err := h.workforce.UpdateEmployee(r.Context(), h.actorUserID, workforce.EmployeeProfileInput{
		UserID:           userID,
		DepartmentID:     workforce.DepartmentID(payload.DepartmentID),
		Title:            payload.Title,
		SupervisorUserID: identity.UserID(payload.SupervisorUserID),
	}, request.ID(r.Context()))
	if err != nil {
		h.writeMSCWorkforceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, toEmployeeMutationResponse(profile))
}

func (h *MSCWriteHandlers) OffboardEmployee(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		WriteNotFound(w, r)
		return
	}
	body, ok := readMSCWriteBody(w, r)
	if !ok {
		return
	}
	if _, ok := h.authorize(w, r, mscaccess.CapabilityEmployeeWrite, body); !ok {
		return
	}
	userID, valid := managedUserID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	result, err := h.workforce.OffboardEmployee(r.Context(), h.actorUserID, userID, request.ID(r.Context()))
	if err != nil {
		h.writeMSCWorkforceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, map[string]any{
		"status": string(result.Status), "sessionCleanupPending": result.CleanupPending,
	})
}

func (h *MSCWriteHandlers) CreateDepartment(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		WriteNotFound(w, r)
		return
	}
	body, ok := readMSCWriteBody(w, r)
	if !ok {
		return
	}
	if _, ok := h.authorize(w, r, mscaccess.CapabilityDepartmentWrite, body); !ok {
		return
	}
	payload, ok := decodeMSCWritePayload[mscDepartmentMutationRequest](w, r, body)
	if !ok {
		return
	}
	detail, err := h.workforce.CreateDepartment(r.Context(), h.actorUserID, workforce.DepartmentInput{
		Name:               payload.Name,
		ParentDepartmentID: workforce.DepartmentID(payload.ParentDepartmentID),
		OwnerUserID:        identity.UserID(payload.OwnerUserID),
	}, request.ID(r.Context()))
	if err != nil {
		h.writeMSCWorkforceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusCreated, toDepartmentDetailResponse(detail))
}

func (h *MSCWriteHandlers) UpdateDepartment(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		WriteNotFound(w, r)
		return
	}
	body, ok := readMSCWriteBody(w, r)
	if !ok {
		return
	}
	if _, ok := h.authorize(w, r, mscaccess.CapabilityDepartmentWrite, body); !ok {
		return
	}
	departmentID, valid := departmentIDFromPath(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	payload, ok := decodeMSCWritePayload[mscDepartmentPatchRequest](w, r, body)
	if !ok {
		return
	}
	patch := workforce.DepartmentPatch{Name: payload.Name}
	if payload.ParentDepartmentID.Set {
		value := workforce.DepartmentID(payload.ParentDepartmentID.Value)
		patch.ParentDepartmentID = &value
	}
	if payload.OwnerUserID.Set {
		value := identity.UserID(payload.OwnerUserID.Value)
		patch.OwnerUserID = &value
	}
	detail, err := h.workforce.UpdateDepartment(r.Context(), h.actorUserID, departmentID, patch, request.ID(r.Context()))
	if err != nil {
		h.writeMSCWorkforceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, toDepartmentDetailResponse(detail))
}

func (h *MSCWriteHandlers) DeleteDepartment(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		WriteNotFound(w, r)
		return
	}
	body, ok := readMSCWriteBody(w, r)
	if !ok {
		return
	}
	if _, ok := h.authorize(w, r, mscaccess.CapabilityDepartmentWrite, body); !ok {
		return
	}
	departmentID, valid := departmentIDFromPath(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	if err := h.workforce.DeleteDepartment(r.Context(), h.actorUserID, departmentID, request.ID(r.Context())); err != nil {
		h.writeMSCWorkforceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
