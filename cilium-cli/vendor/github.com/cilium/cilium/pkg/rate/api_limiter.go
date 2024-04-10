// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rate

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var (
	log              = logging.DefaultLogger.WithField(logfields.LogSubsys, "rate")
	ErrWaitCancelled = errors.New("request cancelled while waiting for rate limiting slot")
)

const (
	defaultMeanOver                = 10
	defaultDelayedAdjustmentFactor = 0.50
	defaultMaxAdjustmentFactor     = 100.0

	// waitSemaphoreWeight is the maximum resolution of the wait semaphore,
	// the higher this value, the more accurate the ParallelRequests
	// requirement is implemented
	waitSemaphoreResolution = 10000000

	// logUUID is the UUID of the request.
	logUUID = "uuid"
	// logAPICallName is the name of the underlying API call, such as
	// "endpoint-create".
	logAPICallName = "name"
	// logProcessingDuration is the time taken to perform the actual underlying
	// API call such as creating an endpoint or deleting an endpoint. This is
	// the time between when the request has finished waiting (or being
	// delayed), to when the underlying action has finished.
	logProcessingDuration = "processingDuration"
	// logParallelRequests is the number of allowed parallel requests. See
	// APILimiter.parallelRequests.
	logParallelRequests = "parallelRequests"
	// logMinWaitDuration represents APILimiterParameters.MinWaitDuration.
	logMinWaitDuration = "minWaitDuration"
	// logMaxWaitDuration represents APILimiterParameters.MaxWaitDuration.
	logMaxWaitDuration = "maxWaitDuration"
	// logMaxWaitDurationLimiter is the actual / calculated maximum threshold
	// for a request to wait. Any request exceeding this threshold will not be
	// processed.
	logMaxWaitDurationLimiter = "maxWaitDurationLimiter"
	// logWaitDurationLimit is the actual / calculated amount of time
	// determined by the underlying rate-limiting library that this request
	// must wait before the rate limiter releases it, so that it can take the
	// underlying action. See golang.org/x/time/rate.(*Reservation).Delay().
	logWaitDurationLimit = "waitDurationLimiter"
	// logWaitDurationTotal is the actual total amount of time that this
	// request spent waiting to be released by the rate limiter.
	logWaitDurationTotal = "waitDurationTotal"
	// logLimit is the rate limit. See APILimiterParameters.RateLimit.
	logLimit = "limit"
	// logLimit is the burst rate. See APILimiterParameters.RateBurst.
	logBurst = "burst"
	// logTotalDuration is the total time between when the request was first
	// scheduled (entered the rate limiter) to when it completed processing of
	// the underlying action. This is the absolute total time of the request
	// from beginning to end.
	logTotalDuration = "totalDuration"
	// logSkipped represents whether the rate limiter will skip rate-limiting
	// this request. See APILimiterParameters.SkipInitial.
	logSkipped = "rateLimiterSkipped"
)

type outcome string

const (
	outcomeParallelMaxWait outcome = "fail-parallel-wait"
	outcomeLimitMaxWait    outcome = "fail-limit-wait"
	outcomeReqCancelled    outcome = "request-cancelled"
	outcomeErrorCode       int     = 429
	outcomeSuccessCode     int     = 200
)

// APILimiter is an extension to x/time/rate.Limiter specifically for Cilium
// API calls. It allows to automatically adjust the rate, burst and maximum
// parallel API calls to stay as close as possible to an estimated processing
// time.
type APILimiter struct {
	// name is the name of the API call. This field is immutable after
	// NewAPILimiter()
	name string

	// params is the parameters of the limiter. This field is immutable
	// after NewAPILimiter()
	params APILimiterParameters

	// metrics points to the metrics implementation provided by the caller
	// of the APILimiter. This field is immutable after NewAPILimiter()
	metrics MetricsObserver

	// mutex protects all fields below this line
	mutex lock.RWMutex

	// meanProcessingDuration is the latest mean processing duration,
	// calculated based on processingDurations
	meanProcessingDuration float64

	// processingDurations is the last params.MeanOver processing durations
	processingDurations []time.Duration

	// meanWaitDuration is the latest mean wait duration, calculated based
	// on waitDurations
	meanWaitDuration float64

	// waitDurations is the last params.MeanOver wait durations
	waitDurations []time.Duration

	// parallelRequests is the currently allowed maximum parallel
	// requests. This defaults to params.MaxParallel requests and is then
	// adjusted automatically if params.AutoAdjust is enabled.
	parallelRequests int

	// adjustmentFactor is the latest adjustment factor. It is the ratio
	// between params.EstimatedProcessingDuration and
	// meanProcessingDuration.
	adjustmentFactor float64

	// limiter is the rate limiter based on params.RateLimit and
	// params.RateBurst.
	limiter *rate.Limiter

	// currentRequestsInFlight is the number of parallel API requests
	// currently in flight
	currentRequestsInFlight int

	// requestsProcessed is the total number of processed requests
	requestsProcessed int64

	// requestsScheduled is the total number of scheduled requests
	requestsScheduled int64

	// parallelWaitSemaphore is the semaphore used to implement
	// params.MaxParallel. It is initialized with a capacity of
	// waitSemaphoreResolution and each API request will acquire
	// waitSemaphoreResolution/params.MaxParallel tokens.
	parallelWaitSemaphore *semaphore.Weighted
}

// APILimiterParameters is the configuration of an APILimiter. The structure
// may not be mutated after it has been passed into NewAPILimiter().
type APILimiterParameters struct {
	// EstimatedProcessingDuration is the estimated duration an API call
	// will take. This value is used if AutoAdjust is enabled to
	// automatically adjust rate limits to stay as close as possible to the
	// estimated processing duration.
	EstimatedProcessingDuration time.Duration

	// AutoAdjust enables automatic adjustment of the values
	// ParallelRequests, RateLimit, and RateBurst in order to keep the
	// mean processing duration close to EstimatedProcessingDuration
	AutoAdjust bool

	// MeanOver is the number of entries to keep in order to calculate the
	// mean processing and wait duration
	MeanOver int

	// ParallelRequests is the parallel requests allowed. If AutoAdjust is
	// enabled, the value will adjust automatically.
	ParallelRequests int

	// MaxParallelRequests is the maximum parallel requests allowed. If
	// AutoAdjust is enabled, then the ParalelRequests will never grow
	// above MaxParallelRequests.
	MaxParallelRequests int

	// MinParallelRequests is the minimum parallel requests allowed. If
	// AutoAdjust is enabled, then the ParallelRequests will never fall
	// below MinParallelRequests.
	MinParallelRequests int

	// RateLimit is the initial number of API requests allowed per second.
	// If AutoAdjust is enabled, the value will adjust automatically.
	RateLimit rate.Limit

	// RateBurst is the initial allowed burst of API requests allowed. If
	// AutoAdjust is enabled, the value will adjust automatically.
	RateBurst int

	// MinWaitDuration is the minimum time an API request always has to
	// wait before the Wait() function returns an error.
	MinWaitDuration time.Duration

	// MaxWaitDuration is the maximum time an API request is allowed to
	// wait before the Wait() function returns an error.
	MaxWaitDuration time.Duration

	// Log enables info logging of processed API requests. This should only
	// be used for low frequency API calls.
	Log bool

	// DelayedAdjustmentFactor is percentage of the AdjustmentFactor to be
	// applied to RateBurst and MaxWaitDuration defined as a value between
	// 0.0..1.0. This is used to steer a slower reaction of the RateBurst
	// and ParallelRequests compared to RateLimit.
	DelayedAdjustmentFactor float64

	// SkipInitial is the number of initial API calls for which to not
	// apply any rate limiting. This is useful to define a learning phase
	// in the beginning to allow for auto adjustment before imposing wait
	// durations and rate limiting on API calls.
	SkipInitial int

	// MaxAdjustmentFactor is the maximum adjustment factor when AutoAdjust
	// is enabled. Base values will not adjust more than by this factor.
	MaxAdjustmentFactor float64
}

// MergeUserConfig merges the provided user configuration into the existing
// parameters and returns a new copy.
func (p APILimiterParameters) MergeUserConfig(config string) (APILimiterParameters, error) {
	if err := (&p).mergeUserConfig(config); err != nil {
		return APILimiterParameters{}, err
	}

	return p, nil
}

// NewAPILimiter returns a new APILimiter based on the parameters and metrics implementation
func NewAPILimiter(name string, p APILimiterParameters, metrics MetricsObserver) *APILimiter {
	if p.MeanOver == 0 {
		p.MeanOver = defaultMeanOver
	}

	if p.MinParallelRequests == 0 {
		p.MinParallelRequests = 1
	}

	if p.RateBurst == 0 {
		p.RateBurst = 1
	}

	if p.DelayedAdjustmentFactor == 0.0 {
		p.DelayedAdjustmentFactor = defaultDelayedAdjustmentFactor
	}

	if p.MaxAdjustmentFactor == 0.0 {
		p.MaxAdjustmentFactor = defaultMaxAdjustmentFactor
	}

	l := &APILimiter{
		name:                  name,
		params:                p,
		parallelRequests:      p.ParallelRequests,
		parallelWaitSemaphore: semaphore.NewWeighted(waitSemaphoreResolution),
		metrics:               metrics,
	}

	if p.RateLimit != 0 {
		l.limiter = rate.NewLimiter(p.RateLimit, p.RateBurst)
	}

	return l
}

// NewAPILimiterFromConfig returns a new APILimiter based on user configuration
func NewAPILimiterFromConfig(name, config string, metrics MetricsObserver) (*APILimiter, error) {
	p := &APILimiterParameters{}

	if err := p.mergeUserConfig(config); err != nil {
		return nil, err
	}

	return NewAPILimiter(name, *p, metrics), nil
}

func (p *APILimiterParameters) mergeUserConfigKeyValue(key, value string) error {
	switch strings.ToLower(key) {
	case "rate-limit":
		limit, err := parseRate(value)
		if err != nil {
			return fmt.Errorf("unable to parse rate %q: %w", value, err)
		}
		p.RateLimit = limit
	case "rate-burst":
		burst, err := parsePositiveInt(value)
		if err != nil {
			return err
		}
		p.RateBurst = burst
	case "min-wait-duration":
		minWaitDuration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("unable to parse duration %q: %w", value, err)
		}
		p.MinWaitDuration = minWaitDuration
	case "max-wait-duration":
		maxWaitDuration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("unable to parse duration %q: %w", value, err)
		}
		p.MaxWaitDuration = maxWaitDuration
	case "estimated-processing-duration":
		estProcessingDuration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("unable to parse duration %q: %w", value, err)
		}
		p.EstimatedProcessingDuration = estProcessingDuration
	case "auto-adjust":
		v, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("unable to parse bool %q: %w", value, err)
		}
		p.AutoAdjust = v
	case "parallel-requests":
		parallel, err := parsePositiveInt(value)
		if err != nil {
			return err
		}
		p.ParallelRequests = parallel
	case "min-parallel-requests":
		minParallel, err := parsePositiveInt(value)
		if err != nil {
			return err
		}
		p.MinParallelRequests = minParallel
	case "max-parallel-requests":
		maxParallel, err := parsePositiveInt(value)
		if err != nil {
			return err
		}
		p.MaxParallelRequests = int(maxParallel)
	case "mean-over":
		meanOver, err := parsePositiveInt(value)
		if err != nil {
			return err
		}
		p.MeanOver = meanOver
	case "log":
		v, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("unable to parse bool %q: %w", value, err)
		}
		p.Log = v
	case "delayed-adjustment-factor":
		delayedAdjustmentFactor, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("unable to parse float %q: %w", value, err)
		}
		p.DelayedAdjustmentFactor = delayedAdjustmentFactor
	case "max-adjustment-factor":
		maxAdjustmentFactor, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("unable to parse float %q: %w", value, err)
		}
		p.MaxAdjustmentFactor = maxAdjustmentFactor
	case "skip-initial":
		skipInitial, err := parsePositiveInt(value)
		if err != nil {
			return err
		}
		p.SkipInitial = skipInitial
	default:
		return fmt.Errorf("unknown rate limiting option %q", key)
	}

	return nil
}

func (p *APILimiterParameters) mergeUserConfig(config string) error {
	tokens := strings.Split(config, ",")
	for _, token := range tokens {
		if token == "" {
			continue
		}

		t := strings.SplitN(token, ":", 2)
		if len(t) != 2 {
			return fmt.Errorf("unable to parse rate limit option %q, must in the form name=option:value[,option:value]", token)
		}

		if err := p.mergeUserConfigKeyValue(t[0], t[1]); err != nil {
			return fmt.Errorf("unable to parse rate limit option %q with value %q: %w", t[0], t[1], err)
		}
	}

	return nil
}

func (l *APILimiter) Parameters() APILimiterParameters {
	return l.params
}

// SetRateLimit sets the rate limit of the limiter. If limiter is unset, a new
// Limiter is created using the rate burst set in the parameters.
func (l *APILimiter) SetRateLimit(limit rate.Limit) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.limiter != nil {
		l.limiter.SetLimit(limit)
	} else {
		l.limiter = rate.NewLimiter(limit, l.params.RateBurst)
	}
}

// SetRateBurst sets the rate burst of the limiter. If limiter is unset, a new
// Limiter is created using the rate limit set in the parameters.
func (l *APILimiter) SetRateBurst(burst int) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.limiter != nil {
		l.limiter.SetBurst(burst)
	} else {
		l.limiter = rate.NewLimiter(l.params.RateLimit, burst)
	}
}

func (l *APILimiter) delayedAdjustment(current, min, max float64) (n float64) {
	n = current * l.adjustmentFactor
	n = current + ((n - current) * l.params.DelayedAdjustmentFactor)
	if min > 0.0 && n < min {
		n = min
	}
	if max > 0.0 && n > max {
		n = max
	}
	return
}

func (l *APILimiter) calculateAdjustmentFactor() float64 {
	f := l.params.EstimatedProcessingDuration.Seconds() / l.meanProcessingDuration
	if f > l.params.MaxAdjustmentFactor {
		f = l.params.MaxAdjustmentFactor
	}
	if f < 1.0/l.params.MaxAdjustmentFactor {
		f = 1.0 / l.params.MaxAdjustmentFactor
	}
	return f
}

func (l *APILimiter) adjustmentLimit(newValue, initialValue float64) float64 {
	return math.Max(initialValue/l.params.MaxAdjustmentFactor, math.Min(initialValue*l.params.MaxAdjustmentFactor, newValue))
}

func (l *APILimiter) adjustedBurst() int {
	newBurst := l.delayedAdjustment(float64(l.params.RateBurst), float64(l.params.MinParallelRequests), 0.0)
	return int(math.Round(l.adjustmentLimit(newBurst, float64(l.params.RateBurst))))
}

func (l *APILimiter) adjustedLimit() rate.Limit {
	newLimit := rate.Limit(float64(l.params.RateLimit) * l.adjustmentFactor)
	return rate.Limit(l.adjustmentLimit(float64(newLimit), float64(l.params.RateLimit)))
}

func (l *APILimiter) adjustedParallelRequests() int {
	newParallelRequests := l.delayedAdjustment(float64(l.params.ParallelRequests),
		float64(l.params.MinParallelRequests), float64(l.params.MaxParallelRequests))
	return int(l.adjustmentLimit(newParallelRequests, float64(l.params.ParallelRequests)))
}

func (l *APILimiter) requestFinished(r *limitedRequest, err error, code int) {
	if r.finished {
		return
	}

	r.finished = true

	var processingDuration time.Duration
	if !r.startTime.IsZero() {
		processingDuration = time.Since(r.startTime)
	}

	totalDuration := time.Since(r.scheduleTime)

	scopedLog := log.WithFields(logrus.Fields{
		logAPICallName:        l.name,
		logUUID:               r.uuid,
		logProcessingDuration: processingDuration,
		logTotalDuration:      totalDuration,
		logWaitDurationTotal:  r.waitDuration,
	})

	if err != nil {
		scopedLog = scopedLog.WithError(err)
	}

	if l.params.Log {
		scopedLog.Info("API call has been processed")
	} else {
		scopedLog.Debug("API call has been processed")
	}

	if r.waitSemaphoreWeight != 0 {
		l.parallelWaitSemaphore.Release(r.waitSemaphoreWeight)
	}

	l.mutex.Lock()

	if !r.startTime.IsZero() {
		l.requestsProcessed++
		l.currentRequestsInFlight--
	}

	// Only auto-adjust ratelimiter using metrics from successful API requests
	if err == nil {
		l.processingDurations = append(l.processingDurations, processingDuration)
		if exceed := len(l.processingDurations) - l.params.MeanOver; exceed > 0 {
			l.processingDurations = l.processingDurations[exceed:]
		}
		l.meanProcessingDuration = calcMeanDuration(l.processingDurations)

		l.waitDurations = append(l.waitDurations, r.waitDuration)
		if exceed := len(l.waitDurations) - l.params.MeanOver; exceed > 0 {
			l.waitDurations = l.waitDurations[exceed:]
		}
		l.meanWaitDuration = calcMeanDuration(l.waitDurations)

		if l.params.AutoAdjust && l.params.EstimatedProcessingDuration != 0 {
			l.adjustmentFactor = l.calculateAdjustmentFactor()
			l.parallelRequests = l.adjustedParallelRequests()

			if l.limiter != nil {
				l.limiter.SetLimit(l.adjustedLimit())

				newBurst := l.adjustedBurst()
				l.limiter.SetBurst(newBurst)
			}
		}
	}

	values := MetricsValues{
		EstimatedProcessingDuration: l.params.EstimatedProcessingDuration.Seconds(),
		WaitDuration:                r.waitDuration,
		MaxWaitDuration:             l.params.MaxWaitDuration,
		MinWaitDuration:             l.params.MinWaitDuration,
		MeanProcessingDuration:      l.meanProcessingDuration,
		MeanWaitDuration:            l.meanWaitDuration,
		ParallelRequests:            l.parallelRequests,
		CurrentRequestsInFlight:     l.currentRequestsInFlight,
		AdjustmentFactor:            l.adjustmentFactor,
		Error:                       err,
		Outcome:                     string(r.outcome),
		ReturnCode:                  code,
	}

	if l.limiter != nil {
		values.Limit = l.limiter.Limit()
		values.Burst = l.limiter.Burst()
	}
	l.mutex.Unlock()

	if l.metrics != nil {
		l.metrics.ProcessedRequest(l.name, values)
	}
}

// calcMeanDuration returns the mean duration in seconds
func calcMeanDuration(durations []time.Duration) float64 {
	total := 0.0
	for _, t := range durations {
		total += t.Seconds()
	}
	return total / float64(len(durations))
}

// LimitedRequest represents a request that is being limited. It is returned
// by Wait() and the caller of Wait() is responsible to call Done() or Error()
// when the API call has been processed or resulted in an error. It is safe to
// call Error() and then Done(). It is not safe to call Done(), Error(), or
// WaitDuration() concurrently.
type LimitedRequest interface {
	Done()
	Error(err error, code int)
	WaitDuration() time.Duration
}

type limitedRequest struct {
	limiter             *APILimiter
	startTime           time.Time
	scheduleTime        time.Time
	waitDuration        time.Duration
	waitSemaphoreWeight int64
	uuid                string
	finished            bool
	outcome             outcome
}

// WaitDuration returns the duration the request had to wait
func (l *limitedRequest) WaitDuration() time.Duration {
	return l.waitDuration
}

// Done must be called when the API request has been successfully processed
func (l *limitedRequest) Done() {
	l.limiter.requestFinished(l, nil, outcomeSuccessCode)
}

// Error must be called when the API request resulted in an error
func (l *limitedRequest) Error(err error, code int) {
	l.limiter.requestFinished(l, err, code)
}

// Wait blocks until the next API call is allowed to be processed. If the
// configured MaxWaitDuration is exceeded, an error is returned. On success, a
// LimitedRequest is returned on which Done() must be called when the API call
// has completed or Error() if an error occurred.
func (l *APILimiter) Wait(ctx context.Context) (LimitedRequest, error) {
	req, err := l.wait(ctx)
	if err != nil {
		l.requestFinished(req, err, outcomeErrorCode)
		return nil, err
	}
	return req, nil
}

// wait implements the API rate limiting delaying functionality. Every error
// message and corresponding log message are documented in
// Documentation/configuration/api-rate-limiting.rst. If any changes related to
// errors or log messages are made to this function, please update the
// aforementioned page as well.
func (l *APILimiter) wait(ctx context.Context) (req *limitedRequest, err error) {
	var (
		limitWaitDuration time.Duration
		r                 *rate.Reservation
	)

	req = &limitedRequest{
		limiter:      l,
		scheduleTime: time.Now(),
		uuid:         uuid.New().String(),
	}

	l.mutex.Lock()

	l.requestsScheduled++

	scopedLog := log.WithFields(logrus.Fields{
		logAPICallName:      l.name,
		logUUID:             req.uuid,
		logParallelRequests: l.parallelRequests,
	})

	if l.params.MaxWaitDuration > 0 {
		scopedLog = scopedLog.WithField(logMaxWaitDuration, l.params.MaxWaitDuration)
	}

	if l.params.MinWaitDuration > 0 {
		scopedLog = scopedLog.WithField(logMinWaitDuration, l.params.MinWaitDuration)
	}

	select {
	case <-ctx.Done():
		if l.params.Log {
			scopedLog.Warning("Not processing API request due to cancelled context")
		}
		l.mutex.Unlock()
		req.outcome = outcomeReqCancelled
		err = fmt.Errorf("%w: %w", ErrWaitCancelled, ctx.Err())
		return
	default:
	}

	skip := l.params.SkipInitial > 0 && l.requestsScheduled <= int64(l.params.SkipInitial)
	if skip {
		scopedLog = scopedLog.WithField(logSkipped, skip)
	}

	parallelRequests := l.parallelRequests
	meanProcessingDuration := l.meanProcessingDuration
	l.mutex.Unlock()

	if l.params.Log {
		scopedLog.Info("Processing API request with rate limiter")
	} else {
		scopedLog.Debug("Processing API request with rate limiter")
	}

	if skip {
		goto skipRateLimiter
	}

	if parallelRequests > 0 {
		waitCtx := ctx
		if l.params.MaxWaitDuration > 0 {
			ctx2, cancel := context.WithTimeout(ctx, l.params.MaxWaitDuration)
			defer cancel()
			waitCtx = ctx2
		}
		w := int64(waitSemaphoreResolution / parallelRequests)
		err2 := l.parallelWaitSemaphore.Acquire(waitCtx, w)
		if err2 != nil {
			if l.params.Log {
				scopedLog.WithError(err2).Warning("Not processing API request. Wait duration for maximum parallel requests exceeds maximum")
			}
			req.outcome = outcomeParallelMaxWait
			err = fmt.Errorf("timed out while waiting to be served with %d parallel requests: %w", parallelRequests, err2)
			return
		}
		req.waitSemaphoreWeight = w
	}
	req.waitDuration = time.Since(req.scheduleTime)

	l.mutex.Lock()
	if l.limiter != nil {
		r = l.limiter.Reserve()
		limitWaitDuration = r.Delay()

		scopedLog = scopedLog.WithFields(logrus.Fields{
			logLimit:                  fmt.Sprintf("%.2f/s", l.limiter.Limit()),
			logBurst:                  l.limiter.Burst(),
			logWaitDurationLimit:      limitWaitDuration,
			logMaxWaitDurationLimiter: l.params.MaxWaitDuration - req.waitDuration,
		})
	}
	l.mutex.Unlock()

	if l.params.MinWaitDuration > 0 && limitWaitDuration < l.params.MinWaitDuration {
		limitWaitDuration = l.params.MinWaitDuration
	}

	if (l.params.MaxWaitDuration > 0 && (limitWaitDuration+req.waitDuration) > l.params.MaxWaitDuration) || limitWaitDuration == rate.InfDuration {
		if l.params.Log {
			scopedLog.Warning("Not processing API request. Wait duration exceeds maximum")
		}

		// The rate limiter should only consider a reservation valid if
		// the request is actually processed. Cancellation of the
		// reservation should happen before we sleep below.
		if r != nil {
			r.Cancel()
		}

		// Instead of returning immediately, pace the caller by
		// sleeping for the mean processing duration. This helps
		// against callers who disrespect 429 error codes and retry
		// immediately.
		if meanProcessingDuration > 0.0 {
			time.Sleep(time.Duration(meanProcessingDuration * float64(time.Second)))
		}

		req.outcome = outcomeLimitMaxWait
		err = fmt.Errorf("request would have to wait %v to be served (maximum wait duration: %v)",
			limitWaitDuration, l.params.MaxWaitDuration-req.waitDuration)
		return
	}

	if limitWaitDuration != 0 {
		select {
		case <-time.After(limitWaitDuration):
		case <-ctx.Done():
			if l.params.Log {
				scopedLog.Warning("Not processing API request due to cancelled context while waiting")
			}
			// The rate limiter should only consider a reservation
			// valid if the request is actually processed.
			if r != nil {
				r.Cancel()
			}

			req.outcome = outcomeReqCancelled
			err = fmt.Errorf("%w: %w", ErrWaitCancelled, ctx.Err())
			return
		}
	}

	req.waitDuration = time.Since(req.scheduleTime)

skipRateLimiter:

	l.mutex.Lock()
	l.currentRequestsInFlight++
	l.mutex.Unlock()

	scopedLog = scopedLog.WithField(logWaitDurationTotal, req.waitDuration)

	if l.params.Log {
		scopedLog.Info("API request released by rate limiter")
	} else {
		scopedLog.Debug("API request released by rate limiter")
	}

	req.startTime = time.Now()
	return req, nil

}

func parseRate(r string) (rate.Limit, error) {
	tokens := strings.SplitN(r, "/", 2)
	if len(tokens) != 2 {
		return 0, fmt.Errorf("not in the form number/interval")
	}

	f, err := strconv.ParseFloat(tokens[0], 64)
	if err != nil {
		return 0, fmt.Errorf("unable to parse float %q: %w", tokens[0], err)
	}

	// Reject rates such as 1/1 or 10/10 as it will default to nanoseconds
	// which is likely unexpected to the user. Require an explicit suffix.
	if _, err := strconv.ParseInt(string(tokens[1]), 10, 64); err == nil {
		return 0, fmt.Errorf("interval %q must contain duration suffix", tokens[1])
	}

	// If duration is provided as "m" or "s", convert it into "1m" or "1s"
	if _, err := strconv.ParseInt(string(tokens[1][0]), 10, 64); err != nil {
		tokens[1] = "1" + tokens[1]
	}

	d, err := time.ParseDuration(tokens[1])
	if err != nil {
		return 0, fmt.Errorf("unable to parse duration %q: %w", tokens[1], err)
	}

	return rate.Limit(f / d.Seconds()), nil
}

// APILimiterSet is a set of APILimiter indexed by name
type APILimiterSet struct {
	limiters map[string]*APILimiter
	metrics  MetricsObserver
}

// MetricsValues is the snapshot of relevant values to feed into the
// MetricsObserver
type MetricsValues struct {
	WaitDuration                time.Duration
	MinWaitDuration             time.Duration
	MaxWaitDuration             time.Duration
	Outcome                     string
	MeanProcessingDuration      float64
	MeanWaitDuration            float64
	EstimatedProcessingDuration float64
	ParallelRequests            int
	Limit                       rate.Limit
	Burst                       int
	CurrentRequestsInFlight     int
	AdjustmentFactor            float64
	Error                       error
	ReturnCode                  int
}

// MetricsObserver is the interface that must be implemented to extract metrics
type MetricsObserver interface {
	// ProcessedRequest is invoked after invocation of an API call
	ProcessedRequest(name string, values MetricsValues)
}

// NewAPILimiterSet creates a new APILimiterSet based on a set of rate limiting
// configurations and the default configuration. Any rate limiter that is
// configured in the config OR the defaults will be configured and made
// available via the Limiter(name) and Wait() function.
func NewAPILimiterSet(config map[string]string, defaults map[string]APILimiterParameters, metrics MetricsObserver) (*APILimiterSet, error) {
	limiters := map[string]*APILimiter{}

	for name, p := range defaults {
		// Merge user config into defaults when provided
		if userConfig, ok := config[name]; ok {
			combinedParams, err := p.MergeUserConfig(userConfig)
			if err != nil {
				return nil, err
			}
			p = combinedParams
		}

		limiters[name] = NewAPILimiter(name, p, metrics)
	}

	for name, c := range config {
		if _, ok := defaults[name]; !ok {
			l, err := NewAPILimiterFromConfig(name, c, metrics)
			if err != nil {
				return nil, fmt.Errorf("unable to parse rate limiting configuration %s=%s: %w", name, c, err)
			}

			limiters[name] = l
		}
	}

	return &APILimiterSet{
		limiters: limiters,
		metrics:  metrics,
	}, nil
}

// Limiter returns the APILimiter with a given name
func (s *APILimiterSet) Limiter(name string) *APILimiter {
	return s.limiters[name]
}

type dummyRequest struct{}

func (d dummyRequest) WaitDuration() time.Duration { return 0 }
func (d dummyRequest) Done()                       {}
func (d dummyRequest) Error(err error, code int)   {}

// Wait invokes Wait() on the APILimiter with the given name. If the limiter
// does not exist, a dummy limiter is used which will not impose any
// restrictions.
func (s *APILimiterSet) Wait(ctx context.Context, name string) (LimitedRequest, error) {
	l, ok := s.limiters[name]
	if !ok {
		return dummyRequest{}, nil
	}

	return l.Wait(ctx)
}

// parsePositiveInt parses value as an int. It returns an error if value cannot
// be parsed or is negative.
func parsePositiveInt(value string) (int, error) {
	switch i64, err := strconv.ParseInt(value, 10, 64); {
	case err != nil:
		return 0, fmt.Errorf("unable to parse positive integer %q: %v", value, err)
	case i64 < 0:
		return 0, fmt.Errorf("unable to parse positive integer %q: negative value", value)
	case i64 > math.MaxInt:
		return 0, fmt.Errorf("unable to parse positive integer %q: overflow", value)
	default:
		return int(i64), nil
	}
}
