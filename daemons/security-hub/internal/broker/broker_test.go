package broker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

func TestBroker_DispatchPollComplete(t *testing.T) {
	b := New()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start agent poller in background
	go func() {
		job, ok := b.Poll(ctx, "NAL Atlas", 2*time.Second)
		if !ok || job == nil {
			return
		}
		if job.Action != ActionScan {
			return
		}
		b.Complete(JobResult{
			JobID:  job.ID,
			Node:   "NAL Atlas",
			Status: "succeeded",
			Items: []models.ManagedItem{
				{Name: "omlx", TargetType: models.TargetDaemon, CurrentVersion: "1.0.0"},
			},
		})
	}()

	// Wait briefly for poller to attach
	time.Sleep(20 * time.Millisecond)
	if !b.IsConnected("nal atlas") {
		t.Fatal("expected NAL Atlas to report connected while polling")
	}

	res, err := b.Dispatch(ctx, "NAL Atlas", ActionScan, nil)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}
	if res.Status != "succeeded" || len(res.Items) != 1 || res.Items[0].Name != "omlx" {
		t.Fatalf("unexpected JobResult: %+v", res)
	}
}

func TestBroker_RejectsMismatchedNodeResultAndCleansUpTimeout(t *testing.T) {
	b := New()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	// Dispatch with no poller -> should time out cleanly and dequeue stale job
	_, err := b.Dispatch(ctx, "NAL Atlas", ActionUpdate, map[string]string{"target_name": "nginx"})
	if err == nil {
		t.Fatal("expected timeout error when no agent is polling")
	}

	// Subsequent poll should NOT receive the expired job
	pollCtx, pollCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer pollCancel()
	if job, ok := b.Poll(pollCtx, "NAL Atlas", 30*time.Millisecond); ok || job != nil {
		t.Fatalf("expected expired job to be removed from queue, got %+v", job)
	}

	// Verify node-spoofed Complete is rejected
	dCtx, dCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dCancel()
	done := make(chan *JobResult, 1)
	go func() {
		res, _ := b.Dispatch(dCtx, "NAL Atlas", ActionRollback, map[string]string{"service_name": "db"})
		done <- res
	}()

	job, ok := b.Poll(dCtx, "NAL Atlas", 2*time.Second)
	if !ok || job == nil {
		t.Fatal("expected rollback job")
	}
	var payload map[string]string
	_ = json.Unmarshal(job.Payload, &payload)
	if payload["service_name"] != "db" {
		t.Fatalf("expected service_name=db in payload, got %v", payload)
	}
	if b.Complete(JobResult{JobID: job.ID, Node: "EvilNode", Status: "succeeded"}) {
		t.Fatal("expected Complete to reject mismatched node name")
	}
	if !b.Complete(JobResult{JobID: job.ID, Node: "NAL Atlas", Status: "succeeded"}) {
		t.Fatal("expected Complete to accept matching node name")
	}
	got := <-done
	if got == nil || got.Status != "succeeded" {
		t.Fatalf("expected succeeded result, got %+v", got)
	}
}
