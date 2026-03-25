package drainvalidation

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"slices"
	"time"

	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/simplecache"
)

// IPChecker resolves hostnames and checks IP addresses against a blacklist.
type IPChecker interface {
	ResolveAddr(host string) (net.IP, error)
	CheckBlacklist(ip net.IP) error
}

// Reason identifies why a drain URL was rejected.
type Reason int

const (
	ReasonParseFailed   Reason = iota // url.Parse returned an error
	ReasonInvalidScheme               // scheme not in allowed list
	ReasonEmptyHost                   // u.Host is empty
	ReasonCachedFailure               // host found in failed-hosts cache
	ReasonResolveFailed               // DNS resolution failed
	ReasonBlacklisted                 // resolved IP is in a blacklist range
	ReasonBadKeyPair                  // tls.X509KeyPair failed
	ReasonBadCA                       // CA PEM could not be parsed
)

// AllowedSchemes is the canonical list of valid drain URL schemes.
var AllowedSchemes = []string{"syslog", "syslog-tls", "https", "https-batch"}

// Error holds a validation failure and the sanitized URL string.
type Error struct {
	Reason       Reason
	AnonymousURL string
	Err          error
}

func (e *Error) Error() string {
	switch e.Reason {
	case ReasonParseFailed:
		return fmt.Sprintf("cannot parse drain url: %v", e.Err)
	case ReasonInvalidScheme:
		return fmt.Sprintf("invalid scheme for drain url %s", e.AnonymousURL)
	case ReasonEmptyHost:
		return fmt.Sprintf("no hostname in drain url %s", e.AnonymousURL)
	case ReasonCachedFailure:
		return fmt.Sprintf("skipped resolution for drain url %s due to prior failure", e.AnonymousURL)
	case ReasonResolveFailed:
		return fmt.Sprintf("cannot resolve drain url %s: %v", e.AnonymousURL, e.Err)
	case ReasonBlacklisted:
		return fmt.Sprintf("drain url %s resolves to blacklisted IP", e.AnonymousURL)
	case ReasonBadKeyPair:
		return fmt.Sprintf("failed to load certificate for %s: %v", e.AnonymousURL, e.Err)
	case ReasonBadCA:
		return fmt.Sprintf("failed to load root CA for %s", e.AnonymousURL)
	default:
		return "unknown validation error"
	}
}

// Validator performs drain URL validation with DNS failure caching.
type Validator struct {
	ipChecker   IPChecker
	failedHosts *simplecache.SimpleCache[string, bool]
}

// NewValidator creates a Validator. failedHostTTL controls how long
// unresolvable hosts are cached to avoid repeated DNS lookups.
func NewValidator(checker IPChecker, failedHostTTL time.Duration) *Validator {
	return &Validator{
		ipChecker:   checker,
		failedHosts: simplecache.New[string, bool](failedHostTTL),
	}
}

// ValidateURL checks a drain URL string. It performs: parse, scheme check,
// host presence check, failed-host cache lookup, DNS resolution, and
// blacklist check. Returns nil on success.
func (v *Validator) ValidateURL(rawURL string) *Error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return &Error{Reason: ReasonParseFailed, Err: err}
	}

	anon := AnonymizeURL(rawURL)

	if !isAllowedScheme(u.Scheme) {
		return &Error{Reason: ReasonInvalidScheme, AnonymousURL: anon}
	}

	if u.Host == "" {
		return &Error{Reason: ReasonEmptyHost, AnonymousURL: anon}
	}

	if _, cached := v.failedHosts.Get(u.Host); cached {
		return &Error{Reason: ReasonCachedFailure, AnonymousURL: anon}
	}

	ip, err := v.ipChecker.ResolveAddr(u.Host)
	if err != nil {
		v.failedHosts.Set(u.Host, true)
		return &Error{Reason: ReasonResolveFailed, AnonymousURL: anon, Err: err}
	}

	if err := v.ipChecker.CheckBlacklist(ip); err != nil {
		return &Error{Reason: ReasonBlacklisted, AnonymousURL: anon, Err: err}
	}

	return nil
}

// ValidateKeyPair validates a TLS certificate+key pair.
// Returns nil if certPEM and keyPEM are both empty.
func ValidateKeyPair(certPEM, keyPEM []byte) *Error {
	if len(certPEM) == 0 && len(keyPEM) == 0 {
		return nil
	}
	_, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return &Error{Reason: ReasonBadKeyPair, Err: err}
	}
	return nil
}

// ValidateCA validates a CA certificate PEM.
// Returns nil if caPEM is empty.
func ValidateCA(caPEM []byte) *Error {
	if len(caPEM) == 0 {
		return nil
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPEM) {
		return &Error{Reason: ReasonBadCA}
	}
	return nil
}

// AnonymizeURL parses rawURL and returns it with User and RawQuery stripped.
// Returns the raw input if parsing fails.
func AnonymizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}

func isAllowedScheme(scheme string) bool {
	return slices.Contains(AllowedSchemes, scheme)
}
