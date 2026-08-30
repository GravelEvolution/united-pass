package httpapi

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestCompatibleAvatarUploadRoutesByMultipartField(t *testing.T) {
	for _, tc := range []struct {
		name          string
		field         string
		wantPrimary   int
		wantImmutable int
	}{
		{name: "deployed file field", field: "file", wantPrimary: 1},
		{name: "immutable avatar field", field: "avatar", wantImmutable: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			part, err := writer.CreateFormFile(tc.field, "avatar.png")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = part.Write([]byte("image"))
			_ = writer.Close()

			primaryCalls, immutableCalls := 0, 0
			handler := CompatibleAvatarUpload(
				func(w http.ResponseWriter, _ *http.Request) { primaryCalls++; w.WriteHeader(http.StatusOK) },
				func(w http.ResponseWriter, _ *http.Request) { immutableCalls++; w.WriteHeader(http.StatusCreated) },
			)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/me/avatar", &body)
			req.Header.Set("Content-Type", writer.FormDataContentType())
			handler(httptest.NewRecorder(), req)
			if primaryCalls != tc.wantPrimary || immutableCalls != tc.wantImmutable {
				t.Fatalf("primary=%d immutable=%d", primaryCalls, immutableCalls)
			}
		})
	}
}

func TestAvatarMediaRoutesPreferImmutablePattern(t *testing.T) {
	router := chi.NewRouter()
	router.Get("/media/avatars/{avatarFile:avt_[0-9a-f]+\\.png}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("immutable"))
	})
	router.Get("/media/avatars/{userId}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("deployed"))
	})

	for path, want := range map[string]string{
		"/media/avatars/avt_0123456789abcdef0123456789abcdef.png": "immutable",
		"/media/avatars/user_1":                                   "deployed",
	} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK || recorder.Body.String() != want {
			t.Fatalf("%s: status=%d body=%q, want %q", path, recorder.Code, recorder.Body.String(), want)
		}
	}
}

func TestCompatibleAvatarUploadRejectsAmbiguousFields(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, field := range []string{"file", "avatar"} {
		part, err := writer.CreateFormFile(field, field+".png")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = part.Write([]byte("image"))
	}
	_ = writer.Close()

	calls := 0
	handler := CompatibleAvatarUpload(
		func(http.ResponseWriter, *http.Request) { calls++ },
		func(http.ResponseWriter, *http.Request) { calls++ },
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/avatar", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	recorder := httptest.NewRecorder()
	handler(recorder, req)
	if recorder.Code != http.StatusUnprocessableEntity || calls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, calls, recorder.Body.String())
	}
}
