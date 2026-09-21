package registration

import "time"

// MaxCreateRateMXCohorts bounds the number of independent MX-operator
// counters one registration transaction may touch. Domains publishing more
// distinct unfamiliar operators fail closed during delivery assessment.
const MaxCreateRateMXCohorts = 16

// Limit defines one independent abuse-control bucket. Registration creation
// deliberately uses several buckets so changing email addresses cannot reset
// the client-wide budget.
type Limit struct {
	Max    int
	Window time.Duration
}

type AggregateRatePolicy struct {
	Burst     Limit
	Sustained Limit
}

// CreateRatePolicy applies independent budgets to the exact client address,
// its network prefix, the normalized email, and the client/email pair.
type CreateRatePolicy struct {
	ClientIP         Limit
	ClientNet        Limit
	Email            Limit
	MailboxFamily    Limit
	ClientEmail      Limit
	Global           AggregateRatePolicy
	UnfamiliarDomain AggregateRatePolicy
	UnfamiliarMX     AggregateRatePolicy
	IPv4NetBits      int
	IPv6NetBits      int
}

// CreateRateSubject contains only canonical network strings and SHA-256
// digests. Raw email domains and MX hosts must never cross into Redis keys.
type CreateRateSubject struct {
	ClientIP          string
	ClientNetwork     string
	EmailHash         string
	MailboxFamilyHash string
	DomainHash        string
	MXHashes          []string
	FormIntentHash    string
}

// CreateChainRateOutcome describes whether a browser registration request
// advances the ordinary create buckets or consumes the one free replay bound
// to the same form intent. The replay exists solely for the automatic retry
// after a successful risk challenge.
type CreateChainRateOutcome uint8

const (
	CreateChainRateUnknown CreateChainRateOutcome = iota
	CreateChainRateFirstAllowed
	CreateChainRateReplayAllowed
	CreateChainRateLimited
	CreateChainRateBindingMismatch
	CreateChainRateReplayExhausted
)

func (o CreateChainRateOutcome) Allowed() bool {
	return o == CreateChainRateFirstAllowed || o == CreateChainRateReplayAllowed
}

// RatePolicy keeps public-registration limits independent from password-login
// limits. A registration campaign can therefore be tightened without locking
// existing users out of United Pass.
type RatePolicy struct {
	FormIntent Limit
	// FormIntentDevice prevents one browser from repeatedly spending the
	// public form-intent budget. FormIntentGlobal is evaluated before a new
	// device record or form intent is allocated, so fully rotating proxy and
	// cookie traffic still has a hard distributed ceiling.
	FormIntentDevice Limit
	FormIntentGlobal AggregateRatePolicy
	FormIntentTTL    time.Duration
	AdmissionWait    time.Duration
	Create           CreateRatePolicy
	Verify           Limit
	VerifyGlobal     AggregateRatePolicy
	Resend           Limit
}
