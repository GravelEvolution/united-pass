//go:build windows

package localzitadel

import (
	"errors"
	"os/exec"
	"os/user"
)

// restrictSecretFile removes inherited ACLs before granting access only to
// the current user, LocalSystem and the local Administrators group. os.Chmod
// does not restrict DACLs on Windows, so the platform ACL tool is required.
func restrictSecretFile(path string) error {
	current, err := user.Current()
	if err != nil || current.Uid == "" {
		return errors.New("resolve current Windows identity for local secret ACL")
	}
	command := exec.Command(
		"icacls.exe",
		path,
		"/inheritance:r",
		"/grant:r",
		"*"+current.Uid+":(F)",
		"*S-1-5-18:(F)",
		"*S-1-5-32-544:(F)",
	)
	if err := command.Run(); err != nil {
		return errors.New("restrict local secret file ACL")
	}
	return nil
}
