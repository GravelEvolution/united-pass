package httpapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// TrustedClientIPHeader is an internal hop-by-hop application header. The
// public reverse proxy must overwrite it; it must never forward a caller's
// value. Provider-specific headers (including Alibaba ESA/CDN headers) are
// intentionally interpreted at the gateway, not in the application.
const TrustedClientIPHeader = "X-Moonstone-Client-IP"

type trustedClientIPContextKey struct{}
type trustedClientIPAbuseEligibilityContextKey struct{}

// TrustedClientIP builds middleware that accepts TrustedClientIPHeader only
// from an explicitly trusted transport peer. Invalid or multiple values fail
// safely to the transport peer rather than to X-Forwarded-For.
func TrustedClientIP(trustedProxyCIDRs []string) (func(http.Handler) http.Handler, error) {
	prefixes := make([]netip.Prefix, 0, len(trustedProxyCIDRs))
	for _, raw := range trustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("httpapi: parse trusted proxy CIDR: %w", err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer := peerAddr(r)
			client := peer
			peerIsTrustedProxy := isTrustedProxy(peer, prefixes)
			abuseEligible := !peerIsTrustedProxy
			if peerIsTrustedProxy {
				values := r.Header.Values(TrustedClientIPHeader)
				if len(values) == 1 && !strings.Contains(values[0], ",") {
					if parsed, err := netip.ParseAddr(strings.TrimSpace(values[0])); err == nil {
						client = parsed.Unmap()
						abuseEligible = true
					}
				}
			}
			if client.IsValid() {
				r = r.WithContext(context.WithValue(r.Context(), trustedClientIPContextKey{}, client))
				r = r.WithContext(context.WithValue(r.Context(), trustedClientIPAbuseEligibilityContextKey{}, abuseEligible))
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

// clientIPAbuseEligible is false when a request arrived through a configured
// trusted proxy but the proxy did not supply exactly one valid, overwritten
// client-IP assertion. This prevents a missing gateway header from turning the
// shared proxy address into an account-creation block for every visitor.
func clientIPAbuseEligible(r *http.Request) bool {
	if eligible, ok := r.Context().Value(trustedClientIPAbuseEligibilityContextKey{}).(bool); ok {
		return eligible
	}
	// Direct handler tests and deployments without proxy middleware use the
	// transport peer, which is authoritative for that connection.
	return peerAddr(r).IsValid()
}

func clientIP(r *http.Request) string {
	if address, ok := r.Context().Value(trustedClientIPContextKey{}).(netip.Addr); ok && address.IsValid() {
		return address.Unmap().String()
	}
	if address := peerAddr(r); address.IsValid() {
		return address.Unmap().String()
	}
	return "unknown"
}

func peerAddr(r *http.Request) netip.Addr {
	address := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	parsed, err := netip.ParseAddr(strings.Trim(address, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return parsed.Unmap()
}

func isTrustedProxy(peer netip.Addr, prefixes []netip.Prefix) bool {
	if !peer.IsValid() {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(peer) {
			return true
		}
	}
	return false
}

func clientNetwork(client string, ipv4Bits, ipv6Bits int) string {
	address, err := netip.ParseAddr(client)
	if err != nil {
		return "unknown"
	}
	address = address.Unmap()
	bits := ipv6Bits
	if address.Is4() {
		bits = ipv4Bits
	}
	if bits < 0 || bits > address.BitLen() {
		return "unknown"
	}
	return netip.PrefixFrom(address, bits).Masked().String()
}
