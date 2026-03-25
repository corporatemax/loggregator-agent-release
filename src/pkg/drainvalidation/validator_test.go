package drainvalidation_test

import (
	"errors"
	"net"
	"time"

	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/drainvalidation"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type stubIPChecker struct {
	resolveIP  net.IP
	resolveErr error

	blacklistErr error
}

func (s *stubIPChecker) ResolveAddr(host string) (net.IP, error) {
	return s.resolveIP, s.resolveErr
}

func (s *stubIPChecker) CheckBlacklist(ip net.IP) error {
	return s.blacklistErr
}

var _ = Describe("Validator", func() {
	var (
		checker   *stubIPChecker
		validator *drainvalidation.Validator
	)

	BeforeEach(func() {
		checker = &stubIPChecker{
			resolveIP: net.IPv4(127, 0, 0, 1),
		}
		validator = drainvalidation.NewValidator(checker, 120*time.Second)
	})

	Describe("ValidateURL", func() {
		It("accepts a valid syslog URL", func() {
			Expect(validator.ValidateURL("syslog://example.com:514")).To(BeNil())
		})

		It("accepts all allowed schemes", func() {
			for _, scheme := range drainvalidation.AllowedSchemes {
				Expect(validator.ValidateURL(scheme + "://example.com")).To(BeNil())
			}
		})

		It("rejects an unparseable URL", func() {
			vErr := validator.ValidateURL("://bad")
			Expect(vErr).NotTo(BeNil())
			Expect(vErr.Reason).To(Equal(drainvalidation.ReasonParseFailed))
			Expect(vErr.Err).NotTo(BeNil())
		})

		It("rejects an invalid scheme", func() {
			vErr := validator.ValidateURL("ftp://example.com")
			Expect(vErr).NotTo(BeNil())
			Expect(vErr.Reason).To(Equal(drainvalidation.ReasonInvalidScheme))
			Expect(vErr.AnonymousURL).To(Equal("ftp://example.com"))
		})

		It("rejects a URL with no host", func() {
			vErr := validator.ValidateURL("syslog:/no-host")
			Expect(vErr).NotTo(BeNil())
			Expect(vErr.Reason).To(Equal(drainvalidation.ReasonEmptyHost))
		})

		It("rejects a URL when DNS resolution fails", func() {
			checker.resolveErr = errors.New("dns failure")
			vErr := validator.ValidateURL("syslog://unresolvable.example.com")
			Expect(vErr).NotTo(BeNil())
			Expect(vErr.Reason).To(Equal(drainvalidation.ReasonResolveFailed))
			Expect(vErr.Err).To(MatchError("dns failure"))
		})

		It("caches DNS resolution failures", func() {
			checker.resolveErr = errors.New("dns failure")
			Expect(validator.ValidateURL("syslog://unresolvable.example.com")).NotTo(BeNil())

			// Second call should hit cache even if resolver is now fixed
			checker.resolveErr = nil
			vErr := validator.ValidateURL("syslog://unresolvable.example.com")
			Expect(vErr).NotTo(BeNil())
			Expect(vErr.Reason).To(Equal(drainvalidation.ReasonCachedFailure))
		})

		It("rejects a blacklisted IP", func() {
			checker.blacklistErr = errors.New("blacklisted")
			vErr := validator.ValidateURL("syslog://10.0.0.5:514")
			Expect(vErr).NotTo(BeNil())
			Expect(vErr.Reason).To(Equal(drainvalidation.ReasonBlacklisted))
		})

		It("strips credentials and query params from AnonymousURL", func() {
			vErr := validator.ValidateURL("ftp://user:pass@example.com?secret=token")
			Expect(vErr).NotTo(BeNil())
			Expect(vErr.AnonymousURL).To(Equal("ftp://example.com"))
		})
	})

	Describe("ValidateKeyPair", func() {
		It("returns nil for empty cert and key", func() {
			Expect(drainvalidation.ValidateKeyPair(nil, nil)).To(BeNil())
		})

		It("returns an error for invalid cert/key pair", func() {
			vErr := drainvalidation.ValidateKeyPair([]byte("bad-cert"), []byte("bad-key"))
			Expect(vErr).NotTo(BeNil())
			Expect(vErr.Reason).To(Equal(drainvalidation.ReasonBadKeyPair))
			Expect(vErr.Err).NotTo(BeNil())
		})
	})

	Describe("ValidateCA", func() {
		It("returns nil for empty CA", func() {
			Expect(drainvalidation.ValidateCA(nil)).To(BeNil())
		})

		It("returns an error for invalid CA PEM", func() {
			vErr := drainvalidation.ValidateCA([]byte("bad-ca"))
			Expect(vErr).NotTo(BeNil())
			Expect(vErr.Reason).To(Equal(drainvalidation.ReasonBadCA))
		})
	})

	Describe("AnonymizeURL", func() {
		It("strips user info and query params", func() {
			Expect(drainvalidation.AnonymizeURL("syslog://user:pass@host:514?key=val")).
				To(Equal("syslog://host:514"))
		})

		It("returns the raw input if parsing fails", func() {
			raw := "://bad"
			Expect(drainvalidation.AnonymizeURL(raw)).To(Equal(raw))
		})
	})
})
