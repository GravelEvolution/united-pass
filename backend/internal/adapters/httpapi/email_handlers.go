//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-20
// Description: Loopback-only email sending endpoint used by the DreamUP worker
//

package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/GravelEvolution/united-pass/backend/internal/email"
)

// EmailHandlers serves the loopback-only email sending endpoint. It is not
// exposed through nginx; callers are colocated services such as the DreamUP
// worker. When no SMTP sender is configured the endpoint fails closed.
type EmailHandlers struct {
	sender email.Sender
	token  string
}

// NewEmailHandlers builds an EmailHandlers. A non-empty token gates requests
// via a shared bearer credential.
func NewEmailHandlers(sender email.Sender, token string) *EmailHandlers {
	return &EmailHandlers{sender: sender, token: token}
}

type emailSendRequest struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	HTML    string `json:"html"`
}

// Send delivers a single UTF-8 HTML email to one recipient.
func (h *EmailHandlers) Send(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteBadRequest(w, r, "方法不被允许。")
		return
	}
	if h.sender == nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeProviderUnavailable, "邮件服务未配置。", nil)
		return
	}
	if h.token != "" && !bearerTokenMatches(r.Header.Get("Authorization"), h.token) {
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "未授权。", nil)
		return
	}

	var input emailSendRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&input); err != nil {
		WriteBadRequest(w, r, "请求内容无效。")
		return
	}
	if input.To == "" || input.Subject == "" || input.HTML == "" {
		WriteValidation(w, r, "请求内容无效。", nil)
		return
	}

	if err := h.sender.Send(r.Context(), email.Message{To: input.To, Subject: input.Subject, HTML: input.HTML}); err != nil {
		writeError(w, r, http.StatusBadGateway, CodeProviderUnavailable, "邮件发送失败。", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func bearerTokenMatches(header, token string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix)) == token
}
