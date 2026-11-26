package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/broker"
	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/models"
	"github.com/jaewoook/security-hub/internal/service"
)

func TestStartAgentPoller_ExecutesAndReportsScanJob(t *testing.T) {
	b := broker.New()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/nodes/poll", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-NAL-Node-Token") != "secret-tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		job, ok := b.Poll(r.Context(), r.URL.Query().Get("name"), 200*time.Millisecond)
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(job)
	})
	mux.HandleFunc("/api/nodes/result", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-NAL-Node-Token") != "secret-tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var res broker.JobResult
		if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		b.Complete(res)
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &config.Config{
		NodeName:   "NAL Atlas",
		AgentToken: "secret-tok",
		HubURL:     srv.URL,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := service.StartAgentPoller(ctx, cfg, srv.Client(), func(ctx context.Context, job broker.Job) broker.JobResult {
		return broker.JobResult{
			Status: "succeeded",
			Items: []models.ManagedItem{
				{Name: "brew-git", TargetType: models.TargetBrew, CurrentVersion: "2.48.0"},
			},
		}
	}, 10*time.Millisecond)

	dispatchCtx, dispatchCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dispatchCancel()
	res, err := b.Dispatch(dispatchCtx, "NAL Atlas", broker.ActionScan, nil)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}
	if res.Status != "succeeded" || len(res.Items) != 1 || res.Items[0].Name != "brew-git" {
		t.Fatalf("unexpected result: %+v", res)
	}

	cancel()
	for range errCh {
	}
}
