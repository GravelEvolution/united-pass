//go:build !windows

package localzitadel

import "os"

func restrictSecretFile(path string) error {
	return os.Chmod(path, 0o600)
}
