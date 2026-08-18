package browser

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"go.k6.io/k6/v2/internal/js/modules/k6/browser/chromium"
	"go.k6.io/k6/v2/internal/js/modules/k6/browser/common"
	"go.k6.io/k6/v2/internal/js/modules/k6/browser/env"

	k6modules "go.k6.io/k6/v2/js/modules"
	k6metrics "go.k6.io/k6/v2/metrics"
)

const (
	defaultBrowserAdmissionPollInterval = 250 * time.Millisecond
	defaultBrowserEndpointCooldown      = 5 * time.Second
	browserAdmissionBlockedLogInterval  = 30 * time.Second
)

type browserResourceSnapshot struct {
	availableMemoryMB int64
	memoryKnown       bool
	availableShmMB    int64
	shmKnown          bool
}

type browserResourceProbe func() browserResourceSnapshot

type browserAdmissionMetrics struct {
	active  *k6metrics.Metric
	waiting *k6metrics.Metric
}

type browserAdmissionReporter func(active, waiting int)

type browserAdmissionBlock struct {
	reason               string
	active               int
	waiting              int
	maxActive            int
	minAvailableMemoryMB int
	minAvailableShmMB    int
	resources            browserResourceSnapshot
}

type browserAdmissionBlockedReporter func(block browserAdmissionBlock)

type remoteBrowserEndpoint struct {
	wsURL          string
	active         int
	unhealthyUntil time.Time
}

type browserLease struct {
	registry      *remoteRegistry
	endpointIndex int
	wsURL         string
	once          sync.Once
	onChange      browserAdmissionReporter
}

func (l *browserLease) release() {
	if l == nil || l.registry == nil {
		return
	}
	l.once.Do(func() {
		active, waiting := l.registry.release(l.endpointIndex)
		if l.onChange != nil {
			l.onChange(active, waiting)
		}
	})
}

func (r *remoteRegistry) configureAdmission(envLookup env.LookupFunc) error {
	var err error
	r.maxActiveContexts, err = lookupNonNegativeInt(envLookup, env.BrowserMaxActiveContexts)
	if err != nil {
		return err
	}
	r.minAvailableMemoryMB, err = lookupNonNegativeInt(envLookup, env.BrowserMinAvailableMemoryMB)
	if err != nil {
		return err
	}
	r.minAvailableShmMB, err = lookupNonNegativeInt(envLookup, env.BrowserMinAvailableShmMB)
	if err != nil {
		return err
	}
	r.pollInterval, err = lookupPositiveDuration(
		envLookup, env.BrowserAdmissionPollInterval, defaultBrowserAdmissionPollInterval,
	)
	if err != nil {
		return err
	}
	r.endpointCooldown, err = lookupPositiveDuration(
		envLookup, env.BrowserEndpointCooldown, defaultBrowserEndpointCooldown,
	)
	if err != nil {
		return err
	}
	r.resourceProbe = probeBrowserResources
	r.endpoints = make([]remoteBrowserEndpoint, 0, len(r.wsURLs))
	for _, wsURL := range r.wsURLs {
		r.endpoints = append(r.endpoints, remoteBrowserEndpoint{wsURL: wsURL})
	}
	return nil
}

func lookupNonNegativeInt(envLookup env.LookupFunc, key string) (int, error) {
	value, ok := envLookup(key)
	if !ok || value == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", key)
	}
	return parsed, nil
}

func lookupPositiveDuration(envLookup env.LookupFunc, key string, fallback time.Duration) (time.Duration, error) {
	value, ok := envLookup(key)
	if !ok || value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", key)
	}
	return parsed, nil
}

func (r *remoteRegistry) admissionEnabled() bool {
	return r.maxActiveContexts > 0 || r.minAvailableMemoryMB > 0 || r.minAvailableShmMB > 0
}

func (r *remoteRegistry) endpointCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.endpoints)
}

func (r *remoteRegistry) acquire(
	ctx context.Context, excluded map[int]struct{},
) (*browserLease, error) {
	return r.acquireWithReporter(ctx, excluded, nil)
}

func (r *remoteRegistry) acquireWithReporter(
	ctx context.Context, excluded map[int]struct{}, report browserAdmissionReporter,
) (*browserLease, error) {
	return r.acquireWithTelemetry(ctx, excluded, report, nil)
}

func (r *remoteRegistry) acquireWithTelemetry(
	ctx context.Context,
	excluded map[int]struct{},
	report browserAdmissionReporter,
	reportBlocked browserAdmissionBlockedReporter,
) (*browserLease, error) {
	r.mu.Lock()
	r.waitingContexts++
	active, waiting := r.activeContexts, r.waitingContexts
	r.mu.Unlock()
	if report != nil {
		report(active, waiting)
	}

	for {
		resources := r.resourceProbe()
		now := time.Now()
		r.mu.Lock()
		blockedBy := r.blockReasonLocked(resources)
		endpointIndex := -1
		if blockedBy == "" {
			endpointIndex = r.selectEndpointLocked(now, excluded)
			if r.isRemote && endpointIndex < 0 {
				blockedBy = "endpoint"
			}
		}
		if blockedBy == "" {
			r.waitingContexts--
			r.activeContexts++
			wsURL := ""
			if endpointIndex >= 0 {
				r.endpoints[endpointIndex].active++
				wsURL = r.endpoints[endpointIndex].wsURL
			}
			active, waiting = r.activeContexts, r.waitingContexts
			r.mu.Unlock()
			if report != nil {
				report(active, waiting)
			}
			return &browserLease{
				registry:      r,
				endpointIndex: endpointIndex,
				wsURL:         wsURL,
				onChange:      report,
			}, nil
		}
		shouldReportBlocked := reportBlocked != nil && r.shouldReportBlockedLocked(blockedBy, now)
		block := browserAdmissionBlock{
			reason:               blockedBy,
			active:               r.activeContexts,
			waiting:              r.waitingContexts,
			maxActive:            r.maxActiveContexts,
			minAvailableMemoryMB: r.minAvailableMemoryMB,
			minAvailableShmMB:    r.minAvailableShmMB,
			resources:            resources,
		}
		r.mu.Unlock()
		if shouldReportBlocked {
			reportBlocked(block)
		}

		timer := time.NewTimer(r.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			r.mu.Lock()
			if r.waitingContexts > 0 {
				r.waitingContexts--
			}
			active, waiting = r.activeContexts, r.waitingContexts
			r.mu.Unlock()
			if report != nil {
				report(active, waiting)
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (r *remoteRegistry) blockReasonLocked(resources browserResourceSnapshot) string {
	if r.maxActiveContexts > 0 && r.activeContexts >= r.maxActiveContexts {
		return "capacity"
	}
	if r.minAvailableMemoryMB > 0 && resources.memoryKnown &&
		resources.availableMemoryMB < int64(r.minAvailableMemoryMB) {
		return "memory"
	}
	if r.minAvailableShmMB > 0 && resources.shmKnown &&
		resources.availableShmMB < int64(r.minAvailableShmMB) {
		return "shm"
	}
	return ""
}

func (r *remoteRegistry) shouldReportBlockedLocked(reason string, now time.Time) bool {
	if reason != r.lastBlockedReason || now.Sub(r.lastBlockedLog) >= browserAdmissionBlockedLogInterval {
		r.lastBlockedReason = reason
		r.lastBlockedLog = now
		return true
	}
	return false
}

func (r *remoteRegistry) selectEndpointLocked(now time.Time, excluded map[int]struct{}) int {
	if !r.isRemote {
		return -1
	}
	best := -1
	for offset := range len(r.endpoints) {
		index := (r.nextEndpoint + offset) % len(r.endpoints)
		endpoint := &r.endpoints[index]
		if _, skip := excluded[index]; skip || now.Before(endpoint.unhealthyUntil) {
			continue
		}
		if best < 0 || endpoint.active < r.endpoints[best].active {
			best = index
		}
	}
	if best >= 0 {
		r.nextEndpoint = (best + 1) % len(r.endpoints)
	}
	return best
}

func (r *remoteRegistry) release(endpointIndex int) (active, waiting int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.activeContexts > 0 {
		r.activeContexts--
	}
	if endpointIndex >= 0 && endpointIndex < len(r.endpoints) && r.endpoints[endpointIndex].active > 0 {
		r.endpoints[endpointIndex].active--
	}
	return r.activeContexts, r.waitingContexts
}

func newBrowserAdmissionReporter(
	vu k6modules.VU, admissionMetrics *browserAdmissionMetrics,
) browserAdmissionReporter {
	if admissionMetrics == nil || admissionMetrics.active == nil || admissionMetrics.waiting == nil {
		return nil
	}
	return func(active, waiting int) {
		state := vu.State()
		if state == nil {
			return
		}
		now := time.Now()
		tags := state.Tags.GetCurrentValues().Tags
		k6metrics.PushIfNotDone(vu.Context(), state.Samples, k6metrics.ConnectedSamples{
			Samples: []k6metrics.Sample{
				{
					TimeSeries: k6metrics.TimeSeries{Metric: admissionMetrics.active, Tags: tags},
					Time:       now,
					Value:      float64(active),
				},
				{
					TimeSeries: k6metrics.TimeSeries{Metric: admissionMetrics.waiting, Tags: tags},
					Time:       now,
					Value:      float64(waiting),
				},
			},
			Tags: tags,
			Time: now,
		})
	}
}

func newBrowserAdmissionBlockedReporter(vu k6modules.VU) browserAdmissionBlockedReporter {
	return func(block browserAdmissionBlock) {
		state := vu.State()
		if state == nil {
			return
		}
		state.Logger.Infof(
			"browser admission blocked_by=%s active=%d waiting=%d max_active=%d "+
				"available_memory_mb=%d memory_known=%t min_memory_mb=%d "+
				"available_shm_mb=%d shm_known=%t min_shm_mb=%d",
			block.reason, block.active, block.waiting, block.maxActive,
			block.resources.availableMemoryMB, block.resources.memoryKnown, block.minAvailableMemoryMB,
			block.resources.availableShmMB, block.resources.shmKnown, block.minAvailableShmMB,
		)
	}
}

func (r *remoteRegistry) markEndpointFailed(endpointIndex int) {
	if endpointIndex < 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if endpointIndex < len(r.endpoints) {
		r.endpoints[endpointIndex].unhealthyUntil = time.Now().Add(r.endpointCooldown)
	}
}

func buildAdmittedBrowser(
	ctx, vuCtx context.Context,
	vu k6modules.VU,
	bt *chromium.BrowserType,
	remote *remoteRegistry,
	pids *pidRegistry,
) (*common.Browser, *browserLease, error) {
	excluded := make(map[int]struct{})
	report := newBrowserAdmissionReporter(vu, remote.admissionMetrics)
	reportBlocked := newBrowserAdmissionBlockedReporter(vu)
	for {
		lease, err := remote.acquireWithTelemetry(vuCtx, excluded, report, reportBlocked)
		if err != nil {
			return nil, nil, err
		}

		if !remote.isRemote {
			browser, pid, launchErr := bt.Launch(ctx, vuCtx)
			if launchErr != nil {
				lease.release()
				return nil, nil, launchErr //nolint:wrapcheck
			}
			pids.registerPid(pid)
			return browser, lease, nil
		}

		browser, connectErr := bt.Connect(ctx, vuCtx, lease.wsURL)
		if connectErr == nil {
			return browser, lease, nil
		}

		remote.markEndpointFailed(lease.endpointIndex)
		lease.release()
		excluded[lease.endpointIndex] = struct{}{}
		vu.State().Logger.Warnf(
			"remote browser endpoint %q failed; quarantining it for %s and trying another: %v",
			lease.wsURL, remote.endpointCooldown, connectErr,
		)
		if len(excluded) >= remote.endpointCount() {
			clear(excluded)
		}
	}
}
