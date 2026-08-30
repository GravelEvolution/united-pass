package registration

import "time"

// Limit defines one independent abuse-control bucket. Registration creation
// deliberately uses several buckets so changing email addresses cannot reset
// the client-wide budget.
type Limit struct {
	Max    int
	Window time.Duration
}

// CreateRatePolicy applies independent budgets to the exact client address,
// its network prefix, the normalized email, and the client/email pair.
type CreateRatePolicy struct {
	ClientIP    Limit
	ClientNet   Limit
	Email       Limit
	ClientEmail Limit
	IPv4NetBits int
	IPv6NetBits int
}

// RatePolicy keeps public-registration limits independent from password-login
// limits. A registration campaign can therefore be tightened without locking
// existing users out of United Pass.
type RatePolicy struct {
	FormIntent Limit
	Create     CreateRatePolicy
	Verify     Limit
	Resend     Limit
}
