package postgres

import (
	"errors"
	"sort"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// Authority mutations that can claim or release the same account/contact
// facts must share these exact advisory-lock namespaces. Keeping the key
// construction here prevents the SMS and WeChat paths from accidentally
// taking unrelated locks for the same user or phone.
func authorityUserLockKey(userID identity.UserID) string {
	return "user:" + string(userID)
}

func authorityPhoneLockKey(phone string) string {
	if phone == "" {
		return ""
	}
	return "phone:" + phone
}

func authorityWeChatLockKey(tenantID, subject string) string {
	return "wechat:" + tenantID + ":" + subject
}

// sortedAuthorityLockKeys returns unique keys in the single global order used
// by every multi-key authority transaction. Empty keys are ignored.
func sortedAuthorityLockKeys(keys ...string) []string {
	unique := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if key != "" {
			unique[key] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for key := range unique {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func isAuthoritySerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "40001" || pgErr.Code == "40P01")
}
