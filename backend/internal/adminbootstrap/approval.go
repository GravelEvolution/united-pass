package adminbootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"sort"
	"time"
)

const GrantSuper = "grant_super"

type Approval struct {
	OperatorUserID   string    `json:"operatorUserId"`
	TargetUserID     string    `json:"targetUserId"`
	Action           string    `json:"action"`
	Provider         string    `json:"provider"`
	ProviderTenantID string    `json:"providerTenantId"`
	ProviderSubject  string    `json:"providerSubject"`
	Nonce            string    `json:"nonce"`
	ExpiresAt        time.Time `json:"expiresAt"`
	KeyID            string    `json:"keyId"`
	Signature        string    `json:"signature"`
}

type ApprovalKey struct {
	OperatorUserID string `json:"operatorUserId"`
	KeyID          string `json:"keyId"`
	PublicKey      string `json:"publicKey"`
}

type ApprovalKeyring struct{ keys map[string]ed25519.PublicKey }

func NewApprovalKeyring(keys []ApprovalKey) (*ApprovalKeyring, error) {
	result := &ApprovalKeyring{keys: make(map[string]ed25519.PublicKey, len(keys))}
	for _, item := range keys {
		decoded, err := base64.RawURLEncoding.DecodeString(item.PublicKey)
		key := item.OperatorUserID + "\x00" + item.KeyID
		if err != nil || item.OperatorUserID == "" || item.KeyID == "" || len(decoded) != ed25519.PublicKeySize || result.keys[key] != nil {
			return nil, ErrInvalidApproval
		}
		result.keys[key] = ed25519.PublicKey(append([]byte(nil), decoded...))
	}
	if len(result.keys) < 2 {
		return nil, ErrInvalidApproval
	}
	return result, nil
}

func LoadApprovalKeyring(path string) (*ApprovalKeyring, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, ErrInvalidApproval
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrInvalidApproval
	}
	var document struct {
		Keys []ApprovalKey `json:"keys"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, ErrInvalidApproval
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidApproval
	}
	return NewApprovalKeyring(document.Keys)
}

func canonicalChange(change Change) ([]byte, string, error) {
	type canonical struct {
		Action, TargetUserID, ExpectedUsername, Provider, ProviderTenantID, ProviderSubject string
		EventID, EventSlug, EventDisplayName, SourceVersion                                 string
	}
	raw, err := json.Marshal(canonical{
		Action: change.Action, TargetUserID: string(change.TargetUserID), ExpectedUsername: change.ExpectedUsername,
		Provider: change.Provider, ProviderTenantID: change.ProviderTenantID, ProviderSubject: change.ProviderSubject,
		EventID: change.Event.EventID, EventSlug: change.Event.Slug, EventDisplayName: change.Event.DisplayName, SourceVersion: change.Event.SourceVersion,
	})
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(raw)
	return raw, hex.EncodeToString(digest[:]), nil
}

func CanonicalApprovalPayload(change Change, approval Approval) ([]byte, error) {
	_, requestHash, err := canonicalChange(change)
	if err != nil {
		return nil, err
	}
	type payload struct {
		RequestHash, OperatorUserID, Nonce, KeyID string
		ExpiresAt                                 int64
	}
	return json.Marshal(payload{RequestHash: requestHash, OperatorUserID: approval.OperatorUserID, Nonce: approval.Nonce, KeyID: approval.KeyID, ExpiresAt: approval.ExpiresAt.UTC().Unix()})
}

func verifyApprovals(change Change, approvals []Approval, keyring *ApprovalKeyring, now time.Time) (string, []VerifiedApproval, error) {
	_, hash, err := canonicalChange(change)
	if err != nil || keyring == nil || len(approvals) != 2 {
		return "", nil, ErrInvalidApproval
	}
	operators := map[string]bool{}
	verified := make([]VerifiedApproval, 0, 2)
	for _, approval := range approvals {
		if approval.Action != change.Action || approval.TargetUserID != string(change.TargetUserID) || approval.Provider != change.Provider || approval.ProviderTenantID != change.ProviderTenantID || approval.ProviderSubject != change.ProviderSubject || approval.Nonce == "" || !approval.ExpiresAt.After(now) || approval.ExpiresAt.After(now.Add(24*time.Hour)) || operators[approval.OperatorUserID] {
			return "", nil, ErrInvalidApproval
		}
		key := keyring.keys[approval.OperatorUserID+"\x00"+approval.KeyID]
		signature, decodeErr := base64.RawURLEncoding.DecodeString(approval.Signature)
		payload, payloadErr := CanonicalApprovalPayload(change, approval)
		if decodeErr != nil || payloadErr != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, payload, signature) {
			return "", nil, ErrInvalidApproval
		}
		operators[approval.OperatorUserID] = true
		digest := sha256.Sum256(append(append([]byte(nil), signature...), []byte(approval.OperatorUserID)...))
		verified = append(verified, VerifiedApproval{ID: "aop_" + hex.EncodeToString(digest[:16]), RequestHash: hash, OperatorUserID: approval.OperatorUserID, KeyID: approval.KeyID, Signature: signature, ExpiresAt: approval.ExpiresAt.UTC(), CreatedAt: now})
	}
	sort.Slice(verified, func(i, j int) bool { return verified[i].OperatorUserID < verified[j].OperatorUserID })
	return hash, verified, nil
}
