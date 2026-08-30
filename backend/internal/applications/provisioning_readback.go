//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Authoritative local provisioning-state read-back contracts
//

package applications

import "context"

// ProvisioningFingerprint contains the frozen, non-secret identifiers used
// to locate a one-time bootstrap's local state. A repository matches any
// identifier so a mutable-field drift cannot make an existing provider
// mapping disappear and cause a duplicate creation.
type ProvisioningFingerprint struct {
	ApplicationName        string
	ApplicationDescription string
	ClientName             string
	RedirectURI            string
	LogoutURI              string
	BootstrapRequestPrefix string
}

// ProvisioningState is the unfiltered local application aggregate used only
// by explicit bootstrap verification. Unlike the public management-plane
// projection, it includes non-provisioned clients and recovery flags.
type ProvisioningState struct {
	Application       Application
	Clients           []OAuthClient
	BootstrapAnchored bool
}

// ProvisioningStateReader reads bootstrap candidates without changing them.
// Implementations must include every live provisioning/reconciliation state
// and must not paginate or filter failed rows away.
type ProvisioningStateReader interface {
	FindProvisioningCandidates(context.Context, ProvisioningFingerprint) ([]ProvisioningState, error)
}
