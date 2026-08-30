package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
)

var errDreamUPJWKSUnavailable = errors.New("httpapi: DreamUP JWKS unavailable")

// DreamUPJWKSHandler serves only the public Ed25519 verification material for
// short-lived DreamUP delegation assertions. The representation and ETag are
// frozen at construction so concurrent requests cannot observe partial key
// rotation state.
type DreamUPJWKSHandler struct {
	representation []byte
	etag           string
	contentLength  string
}

func NewDreamUPJWKSHandler(keyring *dreamupdelegation.Keyring) (*DreamUPJWKSHandler, error) {
	if keyring == nil || len(keyring.PublicJWKS()) == 0 || keyring.ETag() == "" {
		return nil, errDreamUPJWKSUnavailable
	}
	return &DreamUPJWKSHandler{
		representation: keyring.PublicJWKS(),
		etag:           keyring.ETag(),
		contentLength:  strconv.Itoa(len(keyring.PublicJWKS())),
	}, nil
}

func (h *DreamUPJWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("ETag", h.etag)
	w.Header().Set("Content-Length", h.contentLength)
	if ifNoneMatchContains(r.Header.Get("If-None-Match"), h.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.representation)
}

// JWKS is a route-friendly alias for ServeHTTP.
func (h *DreamUPJWKSHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	h.ServeHTTP(w, r)
}

func ifNoneMatchContains(header, current string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" {
			return true
		}
		candidate = strings.TrimSpace(strings.TrimPrefix(candidate, "W/"))
		if candidate == current {
			return true
		}
	}
	return false
}
