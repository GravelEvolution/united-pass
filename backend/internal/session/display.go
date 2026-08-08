//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-08
// Description: Display-metadata normalization for the session inventory
//

package session

import (
	"net"
	"strings"
)

// displayMaxBytes caps each display string (ADR-0006 §3). Normalized values
// are short family names, so this is a defensive bound, not a truncation
// policy: anything over the bound is rejected to empty rather than cut.
const displayMaxBytes = 64

// NormalizeUserAgent maps a raw User-Agent header into two display strings
// using a small built-in allowlist (ADR-0006 §3): DeviceDisplay is the OS
// family and ClientDisplay the browser family. Unrecognized or absent values
// return empty strings (the frontend renders 未知设备 / 未知浏览器). No
// location or device fact is fabricated, and the raw UA never leaves the
// record's UserAgentHash.
func NormalizeUserAgent(ua string) (deviceDisplay, clientDisplay string) {
	return normalizeOS(ua), normalizeBrowser(ua)
}

// normalizeOS recognizes the OS family from the UA string. Order matters:
// Android UAs also contain "Linux", and iOS UAs may contain "Macintosh"
// hints on recent Safari versions.
func normalizeOS(ua string) string {
	switch {
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"), strings.Contains(ua, "iPod"):
		return "iOS"
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "Macintosh"), strings.Contains(ua, "Mac OS X"):
		return "macOS"
	case strings.Contains(ua, "Linux"):
		return "Linux"
	default:
		return ""
	}
}

// normalizeBrowser recognizes the browser family. Order matters: Edge UAs
// contain "Chrome" and "Safari"; Chrome UAs contain "Safari".
func normalizeBrowser(ua string) string {
	switch {
	case strings.Contains(ua, "Edg/"), strings.Contains(ua, "EdgA/"), strings.Contains(ua, "Edge/"):
		return "Edge"
	case strings.Contains(ua, "Firefox/"):
		return "Firefox"
	case strings.Contains(ua, "Chrome/"), strings.Contains(ua, "CriOS/"):
		return "Chrome"
	case strings.Contains(ua, "Safari/"):
		return "Safari"
	default:
		return ""
	}
}

// MaskIP returns the masked client IP per ADR-0006 §3: IPv4 keeps the first
// three octets (203.0.113.*), IPv6 keeps the first four groups
// (2001:db8:1:2:*). Missing, empty or unparseable addresses return an empty
// string (rendered 未知 IP). The raw IP is never persisted.
func MaskIP(raw string) string {
	if raw == "" {
		return ""
	}
	// Strip an optional port (host:port form from RemoteAddr).
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}

	if v4 := ip.To4(); v4 != nil {
		return itoa10(int(v4[0])) + "." + itoa10(int(v4[1])) + "." + itoa10(int(v4[2])) + ".*"
	}

	// Canonical IPv6: format via the standard library, then keep the first
	// four groups. "::" compression can shorten the string, so work on the
	// full 16-byte form instead.
	groups := make([]string, 4)
	for i := 0; i < 4; i++ {
		groups[i] = hexGroup(ip[2*i], ip[2*i+1])
	}
	return strings.Join(groups, ":") + ":*"
}

// hexGroup renders one 16-bit IPv6 group in canonical lowercase hex without
// leading zeros ("0" for a zero group).
func hexGroup(hi, lo byte) string {
	v := int(hi)<<8 | int(lo)
	if v == 0 {
		return "0"
	}
	const digits = "0123456789abcdef"
	var buf [4]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v&0xf]
		v >>= 4
	}
	return string(buf[i:])
}

// itoa10 renders a 0-255 value as decimal without importing strconv.
func itoa10(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// clampDisplay enforces the defensive display-length bound. Values over the
// bound become empty (never truncated).
func clampDisplay(s string) string {
	if len(s) > displayMaxBytes {
		return ""
	}
	return s
}
