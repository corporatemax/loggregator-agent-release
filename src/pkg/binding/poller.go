package binding

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	metrics "code.cloudfoundry.org/go-metric-registry"
	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/drainvalidation"
	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/ingress/applog"
)

type Poller struct {
	apiClient       client
	pollingInterval time.Duration
	store           Setter

	logger                     *log.Logger
	bindingRefreshErrorCounter metrics.Counter
	lastBindingCount           metrics.Gauge
	invalidDrains              metrics.Gauge
	blacklistedDrains          metrics.Gauge
	appLogStream               applog.AppLogStream
	validator                  *drainvalidation.Validator
	warn                       bool
}

type client interface {
	Get(int) (*http.Response, error)
}

type Credentials struct {
	Cert string `json:"cert" yaml:"cert"`
	Key  string `json:"key" yaml:"key"`
	CA   string `json:"ca" yaml:"ca"`
	Apps []App  `json:"apps"`
}

type App struct {
	Hostname string `json:"hostname"`
	AppID    string `json:"app_id"`
}

type Binding struct {
	Url         string        `json:"url" yaml:"url"`
	Credentials []Credentials `json:"credentials" yaml:"credentials"`
}

type AggBinding struct {
	Url  string `yaml:"url"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"`
}

type Setter interface {
	Set(bindings []Binding, bindingCount int)
}

func NewPoller(
	ac client,
	pi time.Duration,
	s Setter,
	m Metrics,
	logger *log.Logger,
	logStream applog.AppLogStream,
	validator *drainvalidation.Validator,
	warn bool,
) *Poller {
	opt := metrics.WithMetricLabels(map[string]string{"unit": "total"})

	p := &Poller{
		apiClient:       ac,
		pollingInterval: pi,
		store:           s,
		logger:          logger,
		bindingRefreshErrorCounter: m.NewCounter(
			"binding_refresh_error",
			"Total number of failed requests to the binding provider.",
		),
		lastBindingCount: m.NewGauge(
			"last_binding_refresh_count",
			"Current number of bindings received from binding provider during last refresh.",
		),
		invalidDrains: m.NewGauge(
			"invalid_drains",
			"Count of invalid drains encountered in last binding fetch. Includes blacklisted drains.",
			opt,
		),
		blacklistedDrains: m.NewGauge(
			"blacklisted_drains",
			"Count of blacklisted drains encountered in last binding fetch.",
			opt,
		),
		appLogStream: logStream,
		validator:    validator,
		warn:         warn,
	}
	p.poll()
	return p
}

func (p *Poller) Poll() {
	for {
		p.poll()
		time.Sleep(p.pollingInterval)
	}
}

func (p *Poller) poll() {
	nextID := 0
	var bindings []Binding
	for {
		resp, err := p.apiClient.Get(nextID)
		if err != nil {
			p.bindingRefreshErrorCounter.Add(1)
			p.logger.Printf("failed to get page %d from internal bindings endpoint: %s", nextID, err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			p.logger.Printf(
				"unexpected response from internal bindings endpoint. status code: %d",
				resp.StatusCode,
			)
			return
		}

		var aResp apiResponse
		err = json.NewDecoder(resp.Body).Decode(&aResp)
		if err != nil {
			p.logger.Printf("failed to decode JSON: %s", err)
			return
		}

		bindings = append(bindings, aResp.Results...)
		nextID = aResp.NextID

		if nextID == 0 {
			break
		}
	}

	filteredBindings := p.checkBindings(bindings)

	bindingCount := CalculateBindingCount(filteredBindings)
	p.lastBindingCount.Set(float64(bindingCount))
	p.store.Set(filteredBindings, bindingCount)
}

func (p *Poller) checkBindings(bindings []Binding) []Binding {
	p.logger.Printf("checking bindings - found %d bindings", len(bindings))
	var invalidDrains float64
	var blacklistedDrains float64
	var filteredBindings []Binding

	for _, b := range bindings {
		if len(b.Credentials) == 0 {
			p.logger.Printf("no credentials for %s", b.Url)
			continue
		}

		anonURL := drainvalidation.AnonymizeURL(b.Url)
		vErr := p.validator.ValidateURL(b.Url)

		for _, cred := range b.Credentials {
			if vErr != nil {
				switch vErr.Reason {
				case drainvalidation.ReasonParseFailed:
					if p.warn {
						p.sendAppLogMessage(
							fmt.Sprintf("Cannot parse syslog drain url %s", b.Url),
							cred.Apps,
						)
					}
				case drainvalidation.ReasonInvalidScheme:
					if p.warn {
						p.sendAppLogMessage(
							fmt.Sprintf("Invalid Scheme for syslog drain url %s", b.Url),
							cred.Apps,
						)
					}
				case drainvalidation.ReasonEmptyHost:
					if p.warn {
						p.sendAppLogMessage(
							fmt.Sprintf("No hostname found in syslog drain url %s", b.Url),
							cred.Apps,
						)
					}
				case drainvalidation.ReasonCachedFailure:
					invalidDrains++
					if p.warn {
						p.sendAppLogMessage(
							fmt.Sprintf("Skipped resolve ip address for syslog drain with url %s due to prior failure", anonURL),
							cred.Apps,
						)
					}
				case drainvalidation.ReasonResolveFailed:
					invalidDrains++
					if p.warn {
						p.sendAppLogMessage(
							fmt.Sprintf("Cannot resolve ip address for syslog drain with url %s", anonURL),
							cred.Apps,
						)
					}
				case drainvalidation.ReasonBlacklisted:
					invalidDrains++
					blacklistedDrains++
					if p.warn {
						p.sendAppLogMessage(
							fmt.Sprintf("Resolved ip address for syslog drain with url %s is blacklisted", anonURL),
							cred.Apps,
						)
					}
				}
				continue
			}

			if len(cred.Cert) > 0 && len(cred.Key) > 0 {
				if tlsErr := drainvalidation.ValidateKeyPair([]byte(cred.Cert), []byte(cred.Key)); tlsErr != nil {
					if p.warn {
						p.sendAppLogMessage(
							fmt.Sprintf("failed to load certificate for %s", anonURL),
							cred.Apps,
						)
					}
					continue
				}
			}

			if len(cred.CA) > 0 {
				if caErr := drainvalidation.ValidateCA([]byte(cred.CA)); caErr != nil {
					if p.warn {
						p.sendAppLogMessage(
							fmt.Sprintf("failed to load root CA for %s", anonURL),
							cred.Apps,
						)
					}
					continue
				}
			}

			filteredBindings = append(filteredBindings, b)
		}
	}

	p.blacklistedDrains.Set(blacklistedDrains)
	p.invalidDrains.Set(invalidDrains)
	return filteredBindings
}

func (p *Poller) sendAppLogMessage(msg string, apps []App) {
	for _, app := range apps {
		appId := app.AppID
		if appId == "" {
			continue
		}
		p.appLogStream.Emit(msg, appId)
		p.logger.Printf("%s for app %s", msg, appId)
	}
}

func CalculateBindingCount(bindings []Binding) int {
	apps := make(map[string]bool)
	for _, b := range bindings {
		for _, c := range b.Credentials {
			for _, a := range c.Apps {
				apps[a.AppID] = true
			}
		}
	}
	return len(apps)
}

type apiResponse struct {
	Results []Binding
	NextID  int `json:"next_id"`
}
