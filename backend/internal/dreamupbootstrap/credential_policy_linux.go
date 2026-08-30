//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Linux root-owned DreamUP credential-file policy
//

//go:build linux

package dreamupbootstrap

import (
	"errors"
	"os"
	"syscall"
)

type linuxCredentialSecurityPolicy struct{}

func newCredentialSecurityPolicy() credentialSecurityPolicy {
	return linuxCredentialSecurityPolicy{}
}

func (linuxCredentialSecurityPolicy) validateParent(path string) error {
	if os.Geteuid() != 0 {
		return errors.New("credential policy: root required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("credential policy: unsafe parent")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("credential policy: parent not root owned")
	}
	return nil
}

func (linuxCredentialSecurityPolicy) secureAndValidate(file *os.File) error {
	if os.Geteuid() != 0 || file == nil {
		return errors.New("credential policy: root required")
	}
	// File.Chmod and File.Stat remain bound to the exclusively opened file;
	// a path replacement cannot redirect either permission operation.
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("credential policy: unsafe file mode")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return errors.New("credential policy: unsafe file ownership")
	}
	return file.Sync()
}
