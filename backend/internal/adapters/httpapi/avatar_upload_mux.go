package httpapi

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
)

// CompatibleAvatarUpload selects the deployed filesystem-backed avatar
// contract (multipart field "file") or the earlier immutable PostgreSQL
// contract (field "avatar"). Supporting both fields keeps existing clients
// and previously issued immutable avatar URLs usable during convergence.
func CompatibleAvatarUpload(primary, immutable http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if primary == nil {
			WriteNotFound(w, r)
			return
		}
		if immutable == nil {
			primary(w, r)
			return
		}

		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || !strings.EqualFold(mediaType, "multipart/form-data") || params["boundary"] == "" {
			primary(w, r)
			return
		}

		payload, err := io.ReadAll(io.LimitReader(r.Body, maxAvatarRequestBytes+1))
		if err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				WriteRequestBodyTooLarge(w, r)
			} else {
				WriteBadRequest(w, r, "头像上传请求无法读取。")
			}
			return
		}
		if int64(len(payload)) > maxAvatarRequestBytes {
			WriteRequestBodyTooLarge(w, r)
			return
		}

		form, err := multipart.NewReader(bytes.NewReader(payload), params["boundary"]).ReadForm(maxAvatarRequestBytes)
		if err != nil {
			r.Body = io.NopCloser(bytes.NewReader(payload))
			r.ContentLength = int64(len(payload))
			primary(w, r)
			return
		}
		defer form.RemoveAll()

		hasPrimary := len(form.File["file"]) != 0
		hasImmutable := len(form.File["avatar"]) != 0
		if hasPrimary && hasImmutable {
			WriteValidation(w, r, "请求参数校验失败。", []FieldError{{
				Field: "avatar", Message: "一次只能提交一个头像文件字段。",
			}})
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(payload))
		r.ContentLength = int64(len(payload))
		if hasImmutable {
			immutable(w, r)
			return
		}
		primary(w, r)
	}
}
