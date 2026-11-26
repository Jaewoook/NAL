package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

const (
	ActionScan     = "scan"
	ActionUpdate   = "update"
	ActionRollback = "rollback"

	DefaultPollWait       = 25 * time.Second
	connectedFreshnessTTL = 90 * time.Second
)

// Job represents a remote command queued by the Hub for a polling agent.
type Job struct {
	ID      string          `json:"id"`
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// JobResult is posted back by the agent after executing a Job.
type JobResult struct {
	JobID    string               `json:"job_id"`
	Node     string               `json:"node"`
	Status   string               `json:"status"`
	ErrorMsg string               `json:"error_msg,omitempty"`
	Items    []models.ManagedItem `json:"items,omitempty"`
	Logs     []models.TaskLogLine `json:"logs,omitempty"`
}

type pendingJob struct {
	nodeLower string
	job       Job
	resultCh  chan JobResult
}

type nodeQueue struct {
	jobs       []Job
	notifyCh   chan struct{}
	activePoll int
	lastSeen   time.Time
}

// Broker coordinates reverse-polled commands between the central Hub and remote agents.
type Broker struct {
	mu      sync.Mutex
	queues  map[string]*nodeQueue
	pending map[string]*pendingJob
}

func New() *Broker {
	return &Broker{
		queues:  make(map[string]*nodeQueue),
		pending: make(map[string]*pendingJob),
	}
}

func normalizeNodeKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func (b *Broker) getOrCreateQueueLocked(key string) *nodeQueue {
	q, ok := b.queues[key]
	if !ok {
		q = &nodeQueue{
			notifyCh: make(chan struct{}, 1),
		}
		b.queues[key] = q
	}
	return q
}

func newJobID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("job-%d", time.Now().UnixNano())
	}
	return "job-" + hex.EncodeToString(raw[:])
}

// Poll waits up to wait for a queued Job for nodeName.
// Returns (job, true) if a job was dequeued, or (nil, false) on timeout/cancellation.
func (b *Broker) Poll(ctx context.Context, nodeName string, wait time.Duration) (*Job, bool) {
	key := normalizeNodeKey(nodeName)
	if key == "" {
		return nil, false
	}
	if wait <= 0 {
		wait = DefaultPollWait
	}

	b.mu.Lock()
	q := b.getOrCreateQueueLocked(key)
	q.activePoll++
	q.lastSeen = time.Now().UTC()
	if len(q.jobs) > 0 {
		job := q.jobs[0]
		q.jobs = q.jobs[1:]
		q.activePoll--
		b.mu.Unlock()
		return &job, true
	}
	notifyCh := q.notifyCh
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		if cur, ok := b.queues[key]; ok {
			if cur.activePoll > 0 {
				cur.activePoll--
			}
			cur.lastSeen = time.Now().UTC()
		}
		b.mu.Unlock()
	}()

	timer := time.NewTimer(wait)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, false
		case <-timer.C:
			return nil, false
		case <-notifyCh:
			b.mu.Lock()
			if len(q.jobs) > 0 {
				job := q.jobs[0]
				q.jobs = q.jobs[1:]
				q.lastSeen = time.Now().UTC()
				b.mu.Unlock()
				return &job, true
			}
			b.mu.Unlock()
		}
	}
}

// Dispatch enqueues a job for nodeName and blocks until the agent submits its result or ctx expires.
func (b *Broker) Dispatch(ctx context.Context, nodeName, action string, payload any) (*JobResult, error) {
	key := normalizeNodeKey(nodeName)
	if key == "" {
		return nil, fmt.Errorf("node name is required")
	}

	var rawPayload json.RawMessage
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal job payload: %w", err)
		}
		rawPayload = data
	}

	job := Job{
		ID:      newJobID(),
		Action:  action,
		Payload: rawPayload,
	}
	pj := &pendingJob{
		nodeLower: key,
		job:       job,
		resultCh:  make(chan JobResult, 1),
	}

	b.mu.Lock()
	q := b.getOrCreateQueueLocked(key)
	q.jobs = append(q.jobs, job)
	b.pending[job.ID] = pj
	select {
	case q.notifyCh <- struct{}{}:
	default:
	}
	b.mu.Unlock()

	select {
	case res := <-pj.resultCh:
		return &res, nil
	case <-ctx.Done():
		b.mu.Lock()
		delete(b.pending, job.ID)
		if cur, ok := b.queues[key]; ok {
			filtered := cur.jobs[:0]
			for _, queued := range cur.jobs {
				if queued.ID != job.ID {
					filtered = append(filtered, queued)
				}
			}
			cur.jobs = filtered
		}
		b.mu.Unlock()
		return nil, fmt.Errorf("remote agent %s did not respond to %s job (%w)", nodeName, action, ctx.Err())
	}
}

// Complete delivers an agent's JobResult to the waiting Dispatch call.
// Returns false if the job ID is unknown/expired or the reporting node does not match.
func (b *Broker) Complete(res JobResult) bool {
	if strings.TrimSpace(res.JobID) == "" {
		return false
	}
	b.mu.Lock()
	pj, ok := b.pending[res.JobID]
	if !ok {
		b.mu.Unlock()
		return false
	}
	if res.Node != "" && normalizeNodeKey(res.Node) != pj.nodeLower {
		b.mu.Unlock()
		return false
	}
	delete(b.pending, res.JobID)
	if q, exists := b.queues[pj.nodeLower]; exists {
		q.lastSeen = time.Now().UTC()
	}
	b.mu.Unlock()

	select {
	case pj.resultCh <- res:
	default:
	}
	return true
}

// IsConnected reports whether nodeName has an active poll or polled recently.
func (b *Broker) IsConnected(nodeName string) bool {
	key := normalizeNodeKey(nodeName)
	if key == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	q, ok := b.queues[key]
	if !ok {
		return false
	}
	if q.activePoll > 0 {
		return true
	}
	return !q.lastSeen.IsZero() && time.Since(q.lastSeen) <= connectedFreshnessTTL
}
