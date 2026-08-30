//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Fail-closed credential-file policy outside Linux
//

//go:build !linux

package dreamupbootstrap

import (
	"errors"
	"os"
)

type unsupportedCredentialSecurityPolicy struct{}

func newCredentialSecurityPolicy() credentialSecurityPolicy {
	return unsupportedCredentialSecurityPolicy{}
}

func (unsupportedCredentialSecurityPolicy) validateParent(string) error {
	return errors.New("credential policy: Linux root ownership unavailable")
}

func (unsupportedCredentialSecurityPolicy) secureAndValidate(*os.File) error {
	return errors.New("credential policy: Linux root ownership unavailable")
}
