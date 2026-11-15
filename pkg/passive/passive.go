package passive

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

type EnumerationOptions struct {
	rateLimiter         subscraping.RequestLimiter
	customRateLimiter   *subscraping.CustomRateLimit
	maxResults          int
	maxResponseBodySize int64
	sourceRetries       int
	hedgeDelay          time.Duration
	hedgeDelaySet       bool
}

type EnumerateOption func(opts *EnumerationOptions)

const defaultSourceRetries = 1

// WithRateLimiter borrows a request budget shared across enumerations.
// It overrides per-enumeration limits; sessions do not own its lifetime.
func WithRateLimiter(limiter subscraping.RequestLimiter) EnumerateOption {
	return func(opts *EnumerationOptions) {
		opts.rateLimiter = limiter
	}
}

func WithCustomRateLimit(crl *subscraping.CustomRateLimit) EnumerateOption {
	return func(opts *EnumerationOptions) {
		opts.customRateLimiter = crl
	}
}

// WithMaxResults sets a per-source limit on the number of results emitted.
// A value of 0 (the default) means no limit. Sources that paginate can honor
// this to avoid unnecessary requests (e.g. to stay within API quotas).
func WithMaxResults(maxResults int) EnumerateOption {
	return func(opts *EnumerationOptions) {
		opts.maxResults = maxResults
	}
}

// WithMaxResponseBodySize sets a cap on bytes read from passive-source HTTP
// response bodies. A value of 0 (the default) means no limit.
func WithMaxResponseBodySize(maxResponseBodySize int64) EnumerateOption {
	return func(opts *EnumerationOptions) {
		opts.maxResponseBodySize = maxResponseBodySize
	}
}

// WithSourceRetries sets how many additional attempts each source may make.
// The default is one retry. A retry runs when an attempt ends with an error;
// WithHedgeDelay may start it earlier for a stalled source. Results from every
// attempt are merged.
func WithSourceRetries(retries int) EnumerateOption {
	return func(opts *EnumerationOptions) {
		opts.sourceRetries = max(0, retries)
	}
}

// WithHedgeDelay starts a second, concurrent attempt when a source has not
// produced any result for the given duration. A non-positive delay disables
// hedging; retries after a reported error are still performed.
func WithHedgeDelay(delay time.Duration) EnumerateOption {
	return func(opts *EnumerationOptions) {
		opts.hedgeDelay = delay
		opts.hedgeDelaySet = true
	}
}

// EnumerateSubdomains wraps EnumerateSubdomainsWithCtx with an empty context
func (a *Agent) EnumerateSubdomains(domain string, proxy string, rateLimit int, timeout int, maxEnumTime time.Duration, options ...EnumerateOption) chan subscraping.Result {
	return a.EnumerateSubdomainsWithCtx(context.Background(), domain, proxy, rateLimit, timeout, maxEnumTime, options...)
}

// EnumerateSubdomainsWithCtx enumerates all the subdomains for a given domain
func (a *Agent) EnumerateSubdomainsWithCtx(ctx context.Context, domain string, proxy string, rateLimit int, timeout int, maxEnumTime time.Duration, options ...EnumerateOption) chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		enumerateOptions := EnumerationOptions{sourceRetries: -1}
		for _, enumerateOption := range options {
			enumerateOption(&enumerateOptions)
		}
		if enumerateOptions.sourceRetries < 0 {
			enumerateOptions.sourceRetries = defaultSourceRetries
		}
		if !enumerateOptions.hedgeDelaySet {
			enumerateOptions.hedgeDelay = defaultHedgeDelay(timeout, maxEnumTime)
		}

		var multiRateLimiter *ratelimit.MultiLimiter
		var err error
		borrowedLegacy := false
		if limiter, ok := enumerateOptions.rateLimiter.(*RateLimiter); ok && limiter.legacy != nil {
			multiRateLimiter = limiter.legacy
			borrowedLegacy = true
		} else if enumerateOptions.rateLimiter == nil {
			multiRateLimiter, err = a.buildMultiRateLimiter(ctx, rateLimit, enumerateOptions.customRateLimiter)
		}
		if err != nil {
			results <- subscraping.Result{
				Type: subscraping.Error, Error: fmt.Errorf("could not init multi rate limiter for %s: %s", domain, err),
			}
			return
		}
		session, err := subscraping.NewSession(domain, proxy, multiRateLimiter, timeout)
		if err != nil {
			if !borrowedLegacy && multiRateLimiter != nil {
				multiRateLimiter.Stop()
			}
			results <- subscraping.Result{
				Type: subscraping.Error, Error: fmt.Errorf("could not init passive session for %s: %s", domain, err),
			}
			return
		}
		session.RequestLimiter = enumerateOptions.rateLimiter
		if borrowedLegacy {
			defer session.Client.CloseIdleConnections()
		} else {
			defer session.Close()
		}
		session.MaxResults = enumerateOptions.maxResults
		session.MaxResponseBodySize = enumerateOptions.maxResponseBodySize

		ctx, cancel := context.WithTimeout(ctx, maxEnumTime)

		wg := &sync.WaitGroup{}
		// Run each source in parallel on the target domain
		for _, runner := range a.sources {
			wg.Add(1)
			go a.enumerateSource(ctx, runner, domain, session, enumerateOptions, results, wg)
		}
		wg.Wait()
		cancel()
	}()
	return results
}

// defaultHedgeDelay starts the second attempt of a slow source early enough
// that a timed-out first attempt does not force the enumeration to spend two
// full timeouts in sequence. It is capped to a quarter of maxEnumTime so that
// very small enumeration budgets still leave room for the retry to finish.
func defaultHedgeDelay(timeout int, maxEnumTime time.Duration) time.Duration {
	var delay time.Duration
	if timeout > 0 {
		delay = time.Duration(timeout) * time.Second / 2
	}
	if maxEnumTime > 0 {
		limit := maxEnumTime / 4
		if delay <= 0 || delay > limit {
			delay = limit
		}
	}
	return max(0, delay)
}

type sourceAttemptEvent struct {
	result subscraping.Result
	done   bool
	retry  bool
}

func isRetryableSourceError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{
		"timeout",
		"timed out",
		"deadline exceeded",
		"temporary",
		"connection reset",
		"connection refused",
		"broken pipe",
		"unexpected eof",
		"server busy",
		"too many requests",
		"status code 429",
		"status code 500",
		"status code 502",
		"status code 503",
		"status code 504",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

// enumerateSource runs one source and, when it fails or stalls, makes a bounded
// second attempt. Results from every attempt are forwarded and de-duplicated so
// a partial first response never hides records returned by the retry.
func (a *Agent) enumerateSource(ctx context.Context, source subscraping.Source, domain string, session *subscraping.Session, options EnumerationOptions, results chan<- subscraping.Result, wg *sync.WaitGroup) {
	defer wg.Done()

	maxAttempts := 1 + options.sourceRetries
	events := make(chan sourceAttemptEvent)
	seen := make(map[string]struct{})

	var attemptWG sync.WaitGroup
	var hedgeTimer *time.Timer
	var hedgeC <-chan time.Time
	active := 0
	started := 0
	succeeded := false

	// Clone the session before any source code runs. Sources may customize
	// their session client, and a clone made while the first attempt is active
	// would race with that write.
	attemptSessions := make([]*subscraping.Session, maxAttempts)
	attemptSessions[0] = session
	for i := 1; i < maxAttempts; i++ {
		attemptSessions[i] = session.Clone()
	}

	stopHedge := func() {
		if hedgeTimer != nil {
			if !hedgeTimer.Stop() {
				select {
				case <-hedgeTimer.C:
				default:
				}
			}
		}
		hedgeC = nil
	}
	resetHedge := func() {
		if maxAttempts <= 1 || started >= maxAttempts || succeeded || options.hedgeDelay <= 0 {
			stopHedge()
			return
		}
		if hedgeTimer == nil {
			hedgeTimer = time.NewTimer(options.hedgeDelay)
		} else {
			if !hedgeTimer.Stop() {
				select {
				case <-hedgeTimer.C:
				default:
				}
			}
			hedgeTimer.Reset(options.hedgeDelay)
		}
		hedgeC = hedgeTimer.C
	}
	startAttempt := func() {
		if started >= maxAttempts {
			return
		}
		started++
		attempt := started
		active++
		attemptWG.Add(1)
		go func() {
			defer attemptWG.Done()
			a.forwardSourceAttempt(ctx, source, domain, attemptSessions[attempt-1], events)
		}()
	}

	defer func() {
		stopHedge()
		// On cancellation the forwarders drain their source channels and exit,
		// so waiting here does not leak the per-source goroutines.
		attemptWG.Wait()
	}()

	startAttempt()
	resetHedge()

	for active > 0 {
		select {
		case <-ctx.Done():
			// Stop forwarding, but let forwardSourceAttempt drain each source
			// so sources blocked on an unconditional send can still exit.
			return

		case <-hedgeC:
			hedgeC = nil
			if active == 1 && started < maxAttempts && !succeeded && ctx.Err() == nil {
				startAttempt()
			}

		case event := <-events:
			if event.done {
				active--
				if event.retry {
					if active == 0 && !succeeded && started < maxAttempts && ctx.Err() == nil {
						startAttempt()
						resetHedge()
					}
				} else {
					succeeded = true
					stopHedge()
				}
				continue
			}

			if ctx.Err() != nil {
				return
			}

			if event.result.Type == subscraping.Subdomain {
				if _, ok := seen[event.result.Value]; ok {
					resetHedge()
					continue
				}
				seen[event.result.Value] = struct{}{}
			}

			select {
			case results <- event.result:
			case <-ctx.Done():
				return
			}
			resetHedge()
		}
	}
}

func (a *Agent) forwardSourceAttempt(ctx context.Context, source subscraping.Source, domain string, session *subscraping.Session, events chan<- sourceAttemptEvent) {
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, source.Name())
	sourceResults := source.Run(ctxWithValue, domain, session)
	retryable := false
	lastWasError := false

	for resp := range sourceResults {
		if resp.Type == subscraping.Error {
			lastWasError = true
			if isRetryableSourceError(resp.Error) {
				retryable = true
			}
		} else {
			lastWasError = false
		}
		select {
		case events <- sourceAttemptEvent{result: resp}:
		case <-ctx.Done():
			// Keep draining so the source goroutine is never blocked on a send
			// after the enumeration deadline has expired.
			for range sourceResults {
			}
			return
		}
	}

	select {
	case events <- sourceAttemptEvent{done: true, retry: retryable || lastWasError}:
	case <-ctx.Done():
	}
}

func (a *Agent) buildMultiRateLimiter(ctx context.Context, globalRateLimit int, rateLimit *subscraping.CustomRateLimit) (*ratelimit.MultiLimiter, error) {
	var multiRateLimiter *ratelimit.MultiLimiter
	var err error
	if rateLimit == nil {
		rateLimit = &subscraping.CustomRateLimit{
			Custom: mapsutil.SyncLockMap[string, uint]{
				Map: make(map[string]uint),
			},
			CustomDuration: mapsutil.SyncLockMap[string, time.Duration]{
				Map: make(map[string]time.Duration),
			},
		}
	}
	for _, source := range a.sources {
		rl, duration := resolveSourceRateLimit(globalRateLimit, rateLimit, source.Name())

		if rl > 0 {
			multiRateLimiter, err = addRateLimiter(ctx, multiRateLimiter, source.Name(), rl, duration)
		} else {
			multiRateLimiter, err = addRateLimiter(ctx, multiRateLimiter, source.Name(), math.MaxUint32, time.Millisecond)
		}

		if err != nil {
			if multiRateLimiter != nil {
				multiRateLimiter.Stop()
			}
			return nil, err
		}
	}
	return multiRateLimiter, err
}

// resolveSourceRateLimit returns the effective rate limit and duration for a source.
// Priority: per-source custom limit > global -rl limit > unlimited.
// Duration comes from -rls (e.g. hackertarget=2/m → 2 per minute), defaulting to per-second.
func resolveSourceRateLimit(globalRateLimit int, rateLimit *subscraping.CustomRateLimit, sourceName string) (uint, time.Duration) {
	duration := time.Second // default: requests per second

	sourceLower := strings.ToLower(sourceName)
	if sourceRL, ok := rateLimit.Custom.Get(sourceLower); ok {
		rl := sourceRateLimitOrDefault(uint(max(globalRateLimit, 0)), sourceRL)
		// Use per-source duration from -rls if set (e.g. "2/m" → time.Minute)
		if d, ok := rateLimit.CustomDuration.Get(sourceLower); ok && d > 0 {
			duration = d
		}
		return rl, duration
	}

	// No per-source limit: fall back to global -rl
	if globalRateLimit > 0 {
		return uint(globalRateLimit), duration
	}

	return 0, duration
}

func sourceRateLimitOrDefault(defaultRateLimit uint, sourceRateLimit uint) uint {
	if sourceRateLimit > 0 {
		return sourceRateLimit
	}
	return defaultRateLimit
}

func addRateLimiter(ctx context.Context, multiRateLimiter *ratelimit.MultiLimiter, key string, maxCount uint, duration time.Duration) (*ratelimit.MultiLimiter, error) {
	if multiRateLimiter == nil {
		mrl, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
			Key:         key,
			IsUnlimited: maxCount == math.MaxUint32,
			MaxCount:    maxCount,
			Duration:    duration,
		})
		return mrl, err
	}
	err := multiRateLimiter.Add(&ratelimit.Options{
		Key:         key,
		IsUnlimited: maxCount == math.MaxUint32,
		MaxCount:    maxCount,
		Duration:    duration,
	})
	return multiRateLimiter, err
}

func (a *Agent) GetStatistics() map[string]subscraping.Statistics {
	stats := make(map[string]subscraping.Statistics)
	sort.Slice(a.sources, func(i, j int) bool {
		return a.sources[i].Name() > a.sources[j].Name()
	})

	for _, source := range a.sources {
		stats[source.Name()] = source.Statistics()
	}
	return stats
}
