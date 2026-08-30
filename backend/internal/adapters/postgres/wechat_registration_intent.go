package postgres

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
	"golang.org/x/crypto/argon2"
)

const (
	wechatIntentMemoryKiB   = 32 * 1024
	wechatIntentIterations  = 2
	wechatIntentParallelism = 1
	wechatIntentSaltBytes   = 16
	wechatIntentKeyBytes    = 32
)

func hashWeChatProviderIntent(intent wechatregistration.ProviderIntent) (string, error) {
	digest, err := digestWeChatProviderIntent(intent)
	if err != nil {
		return "", err
	}
	salt := make([]byte, wechatIntentSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.New("postgres: generate WeChat provider intent salt")
	}
	derived := argon2.IDKey(digest[:], salt, wechatIntentIterations, wechatIntentMemoryKiB, wechatIntentParallelism, wechatIntentKeyBytes)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, wechatIntentMemoryKiB, wechatIntentIterations, wechatIntentParallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(derived)), nil
}

func verifyWeChatProviderIntent(intent wechatregistration.ProviderIntent, verifier string) (bool, error) {
	parts := strings.Split(verifier, "$")
	parameters := "m=" + strconv.Itoa(wechatIntentMemoryKiB) + ",t=" + strconv.Itoa(wechatIntentIterations) + ",p=" + strconv.Itoa(wechatIntentParallelism)
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) || parts[3] != parameters {
		return false, errors.New("postgres: invalid WeChat provider intent verifier")
	}
	salt, saltErr := base64.RawStdEncoding.DecodeString(parts[4])
	expected, keyErr := base64.RawStdEncoding.DecodeString(parts[5])
	if saltErr != nil || keyErr != nil || len(salt) != wechatIntentSaltBytes || len(expected) != wechatIntentKeyBytes {
		return false, errors.New("postgres: invalid WeChat provider intent verifier")
	}
	digest, err := digestWeChatProviderIntent(intent)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey(digest[:], salt, wechatIntentIterations, wechatIntentMemoryKiB, wechatIntentParallelism, wechatIntentKeyBytes)
	return subtle.ConstantTimeCompare(expected, actual) == 1, nil
}

func digestWeChatProviderIntent(intent wechatregistration.ProviderIntent) ([sha256.Size]byte, error) {
	if intent.Username == "" || intent.DisplayName == "" || intent.Email == "" || intent.Password == "" {
		return [sha256.Size]byte{}, errors.New("postgres: incomplete WeChat provider intent")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("united-pass/wechat-registration-provider-intent/v1"))
	for _, field := range []string{intent.Username, intent.DisplayName, strings.ToLower(strings.TrimSpace(intent.Email)), intent.Password} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(field))
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}
