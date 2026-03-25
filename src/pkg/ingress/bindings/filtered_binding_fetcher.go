package bindings

import (
	"log"

	metrics "code.cloudfoundry.org/go-metric-registry"
	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/binding"
	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/drainvalidation"
	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/egress/syslog"
)

// Metrics is the client used to expose gauge and counter metricsClient.
type metricsClient interface {
	NewGauge(name, helpText string, opts ...metrics.MetricOption) metrics.Gauge
}

type FilteredBindingFetcher struct {
	validator         *drainvalidation.Validator
	br                binding.Fetcher
	warn              bool
	logger            *log.Logger
	invalidDrains     metrics.Gauge
	blacklistedDrains metrics.Gauge
}

func NewFilteredBindingFetcher(v *drainvalidation.Validator, b binding.Fetcher, m metricsClient, warn bool, lc *log.Logger) *FilteredBindingFetcher {
	opt := metrics.WithMetricLabels(map[string]string{"unit": "total"})

	invalidDrains := m.NewGauge(
		"invalid_drains",
		"Count of invalid drains encountered in last binding fetch. Includes blacklisted drains.",
		opt,
	)
	blacklistedDrains := m.NewGauge(
		"blacklisted_drains",
		"Count of blacklisted drains encountered in last binding fetch.",
		opt,
	)
	return &FilteredBindingFetcher{
		validator:         v,
		br:                b,
		warn:              warn,
		logger:            lc,
		invalidDrains:     invalidDrains,
		blacklistedDrains: blacklistedDrains,
	}
}

func (f FilteredBindingFetcher) DrainLimit() int {
	return f.br.DrainLimit()
}

func (f *FilteredBindingFetcher) FetchBindings() ([]syslog.Binding, error) {
	sourceBindings, err := f.br.FetchBindings()
	if err != nil {
		return nil, err
	}
	newBindings := []syslog.Binding{}

	var invalidDrains float64
	var blacklistedDrains float64
	for _, b := range sourceBindings {
		vErr := f.validator.ValidateURL(b.Drain.Url)
		if vErr != nil {
			switch vErr.Reason {
			case drainvalidation.ReasonParseFailed:
				invalidDrains++
				f.printWarning("Cannot parse syslog drain url for application %s", b.AppId)
			case drainvalidation.ReasonInvalidScheme:
				f.printWarning("Invalid scheme in syslog drain url %s for application %s", vErr.AnonymousURL, b.AppId)
			case drainvalidation.ReasonEmptyHost:
				invalidDrains++
				f.printWarning("No hostname found in syslog drain url %s for application %s", vErr.AnonymousURL, b.AppId)
			case drainvalidation.ReasonCachedFailure:
				invalidDrains++
				f.printWarning("Skipped resolve ip address for syslog drain with url %s for application %s due to prior failure", vErr.AnonymousURL, b.AppId)
			case drainvalidation.ReasonResolveFailed:
				invalidDrains++
				f.printWarning("Cannot resolve ip address for syslog drain with url %s for application %s", vErr.AnonymousURL, b.AppId)
			case drainvalidation.ReasonBlacklisted:
				invalidDrains++
				blacklistedDrains++
				f.printWarning("Resolved ip address for syslog drain with url %s for application %s is blacklisted", vErr.AnonymousURL, b.AppId)
			}
			continue
		}

		newBindings = append(newBindings, b)
	}

	f.blacklistedDrains.Set(blacklistedDrains)
	f.invalidDrains.Set(invalidDrains)
	return newBindings, nil
}

func (f FilteredBindingFetcher) printWarning(format string, v ...any) {
	if f.warn {
		f.logger.Printf(format, v...)
	}
}
