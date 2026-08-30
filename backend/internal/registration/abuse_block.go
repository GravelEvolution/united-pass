package registration

// AbuseBlockDimension is the fixed vocabulary of registration-abuse block
// dimensions an authenticated operator may revoke. It deliberately contains
// no Redis key or prefix representation.
type AbuseBlockDimension string

const (
	AbuseBlockDevice AbuseBlockDimension = "device"
	AbuseBlockIP     AbuseBlockDimension = "ip"
)

func (d AbuseBlockDimension) Valid() bool {
	return d == AbuseBlockDevice || d == AbuseBlockIP
}
