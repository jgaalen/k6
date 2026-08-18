package browser

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.k6.io/k6/v2/internal/js/modules/k6/browser/env"
)

func admissionLookup(values map[string]string) env.LookupFunc {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestBrowserAdmissionCapsActiveContexts(t *testing.T) {
	t.Parallel()

	registry, err := newRemoteRegistry(admissionLookup(map[string]string{
		env.WebSocketURLs:                "ws://browser-1,ws://browser-2",
		env.BrowserMaxActiveContexts:     "2",
		env.BrowserAdmissionPollInterval: "5ms",
	}))
	require.NoError(t, err)
	registry.resourceProbe = func() browserResourceSnapshot { return browserResourceSnapshot{} }

	first, err := registry.acquire(context.Background(), nil)
	require.NoError(t, err)
	second, err := registry.acquire(context.Background(), nil)
	require.NoError(t, err)

	waitCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err = registry.acquire(waitCtx, nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	first.release()
	third, err := registry.acquire(context.Background(), nil)
	require.NoError(t, err)
	second.release()
	third.release()
}

func TestBrowserAdmissionReportsActiveAndWaitingContexts(t *testing.T) {
	t.Parallel()

	registry, err := newRemoteRegistry(admissionLookup(map[string]string{
		env.WebSocketURLs:                "ws://browser-1",
		env.BrowserMaxActiveContexts:     "1",
		env.BrowserAdmissionPollInterval: "5ms",
	}))
	require.NoError(t, err)
	registry.resourceProbe = func() browserResourceSnapshot { return browserResourceSnapshot{} }

	type counts struct{ active, waiting int }
	reports := make([]counts, 0, 6)
	report := func(active, waiting int) {
		reports = append(reports, counts{active: active, waiting: waiting})
	}

	lease, err := registry.acquireWithReporter(context.Background(), nil, report)
	require.NoError(t, err)
	require.Equal(t, counts{active: 1, waiting: 0}, reports[len(reports)-1])

	waitCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err = registry.acquireWithReporter(waitCtx, nil, report)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Contains(t, reports, counts{active: 1, waiting: 1})
	require.Equal(t, counts{active: 1, waiting: 0}, reports[len(reports)-1])

	lease.release()
	require.Equal(t, counts{active: 0, waiting: 0}, reports[len(reports)-1])
}

func TestBrowserAdmissionReportsWhyAcquisitionIsBlocked(t *testing.T) {
	t.Parallel()

	registry, err := newRemoteRegistry(admissionLookup(map[string]string{
		env.WebSocketURLs:                "ws://browser-1",
		env.BrowserMaxActiveContexts:     "1",
		env.BrowserAdmissionPollInterval: "5ms",
	}))
	require.NoError(t, err)
	registry.resourceProbe = func() browserResourceSnapshot { return browserResourceSnapshot{} }

	lease, err := registry.acquire(context.Background(), nil)
	require.NoError(t, err)

	blocked := make(chan browserAdmissionBlock, 1)
	waitCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err = registry.acquireWithTelemetry(waitCtx, nil, nil, func(block browserAdmissionBlock) {
		select {
		case blocked <- block:
		default:
		}
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)

	reported := <-blocked
	require.Equal(t, "capacity", reported.reason)
	require.Equal(t, 1, reported.active)
	require.Equal(t, 1, reported.waiting)
	require.Equal(t, 1, reported.maxActive)
	lease.release()
}

func TestBrowserAdmissionBalancesAndQuarantinesEndpoints(t *testing.T) {
	t.Parallel()

	registry, err := newRemoteRegistry(admissionLookup(map[string]string{
		env.WebSocketURLs:            "ws://browser-1,ws://browser-2,ws://browser-3",
		env.BrowserMaxActiveContexts: "10",
		env.BrowserEndpointCooldown:  "1h",
	}))
	require.NoError(t, err)
	registry.resourceProbe = func() browserResourceSnapshot { return browserResourceSnapshot{} }

	first, err := registry.acquire(context.Background(), nil)
	require.NoError(t, err)
	second, err := registry.acquire(context.Background(), nil)
	require.NoError(t, err)
	third, err := registry.acquire(context.Background(), nil)
	require.NoError(t, err)
	require.ElementsMatch(t,
		[]string{"ws://browser-1", "ws://browser-2", "ws://browser-3"},
		[]string{first.wsURL, second.wsURL, third.wsURL},
	)

	registry.markEndpointFailed(first.endpointIndex)
	first.release()
	fourth, err := registry.acquire(context.Background(), nil)
	require.NoError(t, err)
	require.NotEqual(t, first.wsURL, fourth.wsURL)

	second.release()
	third.release()
	fourth.release()
}

func TestBrowserAdmissionWaitsForResourceHeadroom(t *testing.T) {
	t.Parallel()

	registry, err := newRemoteRegistry(admissionLookup(map[string]string{
		env.WebSocketURLs:                "ws://browser-1",
		env.BrowserMinAvailableMemoryMB:  "2048",
		env.BrowserMinAvailableShmMB:     "768",
		env.BrowserAdmissionPollInterval: "5ms",
	}))
	require.NoError(t, err)
	registry.resourceProbe = func() browserResourceSnapshot {
		return browserResourceSnapshot{
			availableMemoryMB: 2047,
			memoryKnown:       true,
			availableShmMB:    767,
			shmKnown:          true,
		}
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err = registry.acquire(waitCtx, nil)
	require.True(t, errors.Is(err, context.DeadlineExceeded))

	registry.resourceProbe = func() browserResourceSnapshot {
		return browserResourceSnapshot{
			availableMemoryMB: 4096,
			memoryKnown:       true,
			availableShmMB:    1024,
			shmKnown:          true,
		}
	}
	lease, err := registry.acquire(context.Background(), nil)
	require.NoError(t, err)
	lease.release()
}

func TestBrowserAdmissionRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	_, err := newRemoteRegistry(admissionLookup(map[string]string{
		env.BrowserMaxActiveContexts: "not-a-number",
	}))
	require.EqualError(t, err, "K6_BROWSER_MAX_ACTIVE_CONTEXTS must be a non-negative integer")
}
