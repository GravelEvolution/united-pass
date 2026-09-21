package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
)

import app "github.com/GravelEvolution/united-pass/backend/internal/dreamupadmin"

var personalAssetCreationInputFields = map[string]struct{}{
	"assetId": {}, "assetIdentifier": {}, "catalogId": {}, "description": {},
	"equipmentLabel": {}, "image": {}, "location": {}, "name": {},
	"ownerContact": {}, "ownerDisplayName": {}, "ownerSubject": {},
	"returnAddress": {}, "serialNumber": {},
}

// rewritePersonalAssetCreationBody treats ownerSubject at the browser boundary
// as a stable United Pass user ID. It replaces that field with the verified
// provider subject and adds the original ID under ownerUserId for DreamUP's
// audit projection. Caller-supplied ownerUserId is deliberately not accepted.
func (h *DreamUPAdminHandlers) rewritePersonalAssetCreationBody(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	if h == nil || h.personalAssetOwnerResolver == nil || rejectDuplicateJSONObjectKeys(raw) != nil {
		return nil, app.ErrInvalidRequest
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, app.ErrInvalidRequest
	}
	for field := range fields {
		if _, allowed := personalAssetCreationInputFields[field]; !allowed {
			return nil, app.ErrInvalidRequest
		}
	}
	ownerRaw, ok := fields["ownerSubject"]
	if !ok {
		return nil, app.ErrInvalidRequest
	}
	var userID string
	if err := json.Unmarshal(ownerRaw, &userID); err != nil {
		return nil, app.ErrInvalidRequest
	}
	resolved, err := h.personalAssetOwnerResolver.ResolvePersonalAssetOwner(ctx, userID)
	if err != nil {
		return nil, err
	}
	if string(resolved.UserID) != userID || resolved.ProviderSubject == "" {
		return nil, app.ErrInvalidRequest
	}
	fields["ownerSubject"], err = json.Marshal(resolved.ProviderSubject)
	if err != nil {
		return nil, app.ErrInvalidRequest
	}
	fields["ownerUserId"], err = json.Marshal(userID)
	if err != nil {
		return nil, app.ErrInvalidRequest
	}
	encoded, err := json.Marshal(fields)
	if err != nil || len(encoded) == 0 || len(encoded) > maxDreamUPAdminBodyBytes {
		return nil, app.ErrInvalidRequest
	}
	return encoded, nil
}

// rejectDuplicateJSONObjectKeys recursively checks every object in the body.
// This prevents a parser differential where the BFF resolves one owner while
// an upstream JSON implementation observes a later duplicate field.
func rejectDuplicateJSONObjectKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return app.ErrInvalidRequest
		}
		return err
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return app.ErrInvalidRequest
			}
			if _, duplicate := seen[key]; duplicate {
				return app.ErrInvalidRequest
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		end, endErr := decoder.Token()
		if endErr != nil || end != json.Delim('}') {
			return app.ErrInvalidRequest
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		end, endErr := decoder.Token()
		if endErr != nil || end != json.Delim(']') {
			return app.ErrInvalidRequest
		}
	default:
		return app.ErrInvalidRequest
	}
	return nil
}
