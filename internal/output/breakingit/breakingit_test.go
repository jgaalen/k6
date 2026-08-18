package breakingit

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.k6.io/k6/v2/metrics"
)

func TestBrowserAdmissionStoresAdmittedVUs(t *testing.T) {
	t.Parallel()

	registry := metrics.NewRegistry()
	activeMetric := registry.MustNewMetric("browser_active_vus", metrics.Gauge)
	waitingMetric := registry.MustNewMetric("browser_waiting_vus", metrics.Gauge)
	vusMetric := registry.MustNewMetric("vus", metrics.Gauge)
	tags := registry.RootTagSet()
	now := time.Now()
	logger := &Logger{
		bufVUs:           &bytes.Buffer{},
		envTags:          map[string]string{"run_id": "run", "location": "local", "node_name": "node"},
		browserAdmission: true,
	}

	logger.AddMetricSamples([]metrics.SampleContainer{metrics.ConnectedSamples{
		Samples: []metrics.Sample{
			{TimeSeries: metrics.TimeSeries{Metric: activeMetric, Tags: tags}, Time: now, Value: 7},
			{TimeSeries: metrics.TimeSeries{Metric: waitingMetric, Tags: tags}, Time: now, Value: 13},
			{TimeSeries: metrics.TimeSeries{Metric: vusMetric, Tags: tags}, Time: now, Value: 20},
		},
	}})

	row, err := csv.NewReader(strings.NewReader(logger.bufVUs.String())).Read()
	require.NoError(t, err)
	require.Equal(t, "7", row[4])
	require.EqualValues(t, 7, logger.browserActiveVUs)
	require.EqualValues(t, 13, logger.browserWaitingVUs)
}

func TestRegularRunStoresExecutorVUs(t *testing.T) {
	t.Parallel()

	registry := metrics.NewRegistry()
	vusMetric := registry.MustNewMetric("vus", metrics.Gauge)
	now := time.Now()
	logger := &Logger{
		bufVUs:  &bytes.Buffer{},
		envTags: map[string]string{"run_id": "run", "location": "local", "node_name": "node"},
	}

	logger.AddMetricSamples([]metrics.SampleContainer{metrics.ConnectedSamples{
		Samples: []metrics.Sample{{
			TimeSeries: metrics.TimeSeries{Metric: vusMetric, Tags: registry.RootTagSet()},
			Time:       now,
			Value:      20,
		}},
	}})

	row, err := csv.NewReader(strings.NewReader(logger.bufVUs.String())).Read()
	require.NoError(t, err)
	require.Equal(t, "20", row[4])
}

func TestBrowserAdmissionDoesNotHideExecutorRampDown(t *testing.T) {
	t.Parallel()

	registry := metrics.NewRegistry()
	activeMetric := registry.MustNewMetric("browser_active_vus", metrics.Gauge)
	vusMetric := registry.MustNewMetric("vus", metrics.Gauge)
	now := time.Now()
	logger := &Logger{
		bufVUs:           &bytes.Buffer{},
		envTags:          map[string]string{"run_id": "run", "location": "local", "node_name": "node"},
		browserAdmission: true,
	}
	tags := registry.RootTagSet()

	logger.AddMetricSamples([]metrics.SampleContainer{metrics.ConnectedSamples{
		Samples: []metrics.Sample{
			{TimeSeries: metrics.TimeSeries{Metric: activeMetric, Tags: tags}, Time: now, Value: 7},
			{TimeSeries: metrics.TimeSeries{Metric: vusMetric, Tags: tags}, Time: now, Value: 5},
		},
	}})

	row, err := csv.NewReader(strings.NewReader(logger.bufVUs.String())).Read()
	require.NoError(t, err)
	require.Equal(t, "5", row[4])
}

func TestBrowserAdmissionIgnoresBriefContextHandoff(t *testing.T) {
	t.Parallel()

	registry := metrics.NewRegistry()
	activeMetric := registry.MustNewMetric("browser_active_vus", metrics.Gauge)
	vusMetric := registry.MustNewMetric("vus", metrics.Gauge)
	tags := registry.RootTagSet()
	now := time.Now()
	logger := &Logger{
		bufVUs:           &bytes.Buffer{},
		envTags:          map[string]string{"run_id": "run", "location": "local", "node_name": "node"},
		browserAdmission: true,
	}

	logger.AddMetricSamples([]metrics.SampleContainer{metrics.ConnectedSamples{
		Samples: []metrics.Sample{
			{TimeSeries: metrics.TimeSeries{Metric: activeMetric, Tags: tags}, Time: now, Value: 7},
			{TimeSeries: metrics.TimeSeries{Metric: activeMetric, Tags: tags}, Time: now, Value: 6},
			{TimeSeries: metrics.TimeSeries{Metric: vusMetric, Tags: tags}, Time: now, Value: 20},
			{TimeSeries: metrics.TimeSeries{Metric: vusMetric, Tags: tags}, Time: now.Add(time.Second), Value: 20},
		},
	}})

	rows, err := csv.NewReader(strings.NewReader(logger.bufVUs.String())).ReadAll()
	require.NoError(t, err)
	require.Equal(t, "7", rows[0][4], "the peak hides a release/reacquire handoff")
	require.Equal(t, "6", rows[1][4], "a lower value lasting a full interval remains visible")
}
