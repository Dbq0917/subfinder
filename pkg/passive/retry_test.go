package passive

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type scriptedSource struct {
	mu     sync.Mutex
	runs   int
	script []func(ch chan<- subscraping.Result)
}

func (s *scriptedSource) Run(_ context.Context, _ string, _ *subscraping.Session) <-chan subscraping.Result {
	s.mu.Lock()
	run := s.runs
	s.runs++
	s.mu.Unlock()

	ch := make(chan subscraping.Result, 16)
	go func() {
		defer close(ch)
		if run < len(s.script) {
			s.script[run](ch)
		}
	}()
	return ch
}

func (s *scriptedSource) Name() string                       { return "flaky" }
func (s *scriptedSource) IsDefault() bool                    { return true }
func (s *scriptedSource) HasRecursiveSupport() bool          { return false }
func (s *scriptedSource) NeedsKey() bool                     { return false }
func (s *scriptedSource) AddApiKeys(_ []string)              {}
func (s *scriptedSource) Statistics() subscraping.Statistics { return subscraping.Statistics{} }
func (s *scriptedSource) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}

func (s *scriptedSource) runCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runs
}

func collectSubdomains(t *testing.T, results <-chan subscraping.Result) []string {
	t.Helper()
	var values []string
	for result := range results {
		if result.Type == subscraping.Subdomain {
			values = append(values, result.Value)
		}
	}
	slices.Sort(values)
	return values
}

func TestEnumerationRetriesFailedSourceAndMergesResults(t *testing.T) {
	source := &scriptedSource{script: []func(chan<- subscraping.Result){
		func(ch chan<- subscraping.Result) {
			ch <- subscraping.Result{Source: "flaky", Type: subscraping.Subdomain, Value: "a.example.com"}
			ch <- subscraping.Result{Source: "flaky", Type: subscraping.Error, Error: errors.New("source failed")}
		},
		func(ch chan<- subscraping.Result) {
			ch <- subscraping.Result{Source: "flaky", Type: subscraping.Subdomain, Value: "a.example.com"}
			ch <- subscraping.Result{Source: "flaky", Type: subscraping.Subdomain, Value: "b.example.com"}
		},
	}}
	agent := &Agent{sources: []subscraping.Source{source}}

	values := collectSubdomains(t, agent.EnumerateSubdomainsWithCtx(
		context.Background(), "example.com", "", 0, 1, 2*time.Second,
		WithSourceRetries(1), WithHedgeDelay(0),
	))

	if got, want := values, []string{"a.example.com", "b.example.com"}; !slices.Equal(got, want) {
		t.Fatalf("results = %v, want %v", got, want)
	}
	if got := source.runCount(); got != 2 {
		t.Fatalf("source runs = %d, want 2", got)
	}
}

func TestEnumerationDoesNotRetrySuccessfulSource(t *testing.T) {
	source := &scriptedSource{script: []func(chan<- subscraping.Result){
		func(ch chan<- subscraping.Result) {
			ch <- subscraping.Result{Source: "flaky", Type: subscraping.Subdomain, Value: "a.example.com"}
		},
	}}
	agent := &Agent{sources: []subscraping.Source{source}}

	values := collectSubdomains(t, agent.EnumerateSubdomainsWithCtx(
		context.Background(), "example.com", "", 0, 1, 2*time.Second,
		WithSourceRetries(1), WithHedgeDelay(10*time.Millisecond),
	))

	if got, want := values, []string{"a.example.com"}; !slices.Equal(got, want) {
		t.Fatalf("results = %v, want %v", got, want)
	}
	if got := source.runCount(); got != 1 {
		t.Fatalf("source runs = %d, want 1", got)
	}
}

func TestEnumerationHedgesSlowSourceWithoutSerialTimeout(t *testing.T) {
	const firstAttemptDelay = 200 * time.Millisecond
	source := &scriptedSource{script: []func(chan<- subscraping.Result){
		func(ch chan<- subscraping.Result) {
			time.Sleep(firstAttemptDelay)
			ch <- subscraping.Result{Source: "flaky", Type: subscraping.Error, Error: errors.New("timed out")}
		},
		func(ch chan<- subscraping.Result) {
			ch <- subscraping.Result{Source: "flaky", Type: subscraping.Subdomain, Value: "recovered.example.com"}
		},
	}}
	agent := &Agent{sources: []subscraping.Source{source}}

	start := time.Now()
	values := collectSubdomains(t, agent.EnumerateSubdomainsWithCtx(
		context.Background(), "example.com", "", 0, 1, 2*time.Second,
		WithSourceRetries(1), WithHedgeDelay(25*time.Millisecond),
	))
	elapsed := time.Since(start)

	if got, want := values, []string{"recovered.example.com"}; !slices.Equal(got, want) {
		t.Fatalf("results = %v, want %v", got, want)
	}
	if got := source.runCount(); got != 2 {
		t.Fatalf("source runs = %d, want 2", got)
	}
	// A serial retry would take two full attempt delays. The hedged retry runs
	// alongside the first attempt and must finish close to one attempt delay.
	if elapsed >= 2*firstAttemptDelay {
		t.Fatalf("hedged retry took %s, want less than %s", elapsed, 2*firstAttemptDelay)
	}
}

func TestEnumerationDoesNotRetryAfterCancellation(t *testing.T) {
	source := &scriptedSource{script: []func(chan<- subscraping.Result){
		func(ch chan<- subscraping.Result) {
			time.Sleep(100 * time.Millisecond)
			ch <- subscraping.Result{Source: "flaky", Type: subscraping.Error, Error: errors.New("timed out")}
		},
		func(ch chan<- subscraping.Result) {
			ch <- subscraping.Result{Source: "flaky", Type: subscraping.Subdomain, Value: "late.example.com"}
		},
	}}
	agent := &Agent{sources: []subscraping.Source{source}}

	_ = collectSubdomains(t, agent.EnumerateSubdomainsWithCtx(
		context.Background(), "example.com", "", 0, 1, 20*time.Millisecond,
		WithSourceRetries(1), WithHedgeDelay(0),
	))

	if got := source.runCount(); got != 1 {
		t.Fatalf("source runs after cancellation = %d, want 1", got)
	}
}
