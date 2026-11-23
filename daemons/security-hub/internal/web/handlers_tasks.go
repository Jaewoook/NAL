package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/jaewoook/security-hub/internal/auth"
)

func (s *Server) handleTasksList(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}
	filter := r.URL.Query().Get("type")
	tasks, err := s.store.ListTasks(r.Context(), filter, 50)
	if err != nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "failed to list tasks")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tasks)
}

func (s *Server) handleTaskDetailOrStream(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		auth.WriteJSONError(w, http.StatusInternalServerError, "store is not configured")
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
	parts := strings.Split(trimmed, "/")
	taskID := parts[0]
	if taskID == "" || taskID == "." || taskID == ".." || strings.ContainsAny(taskID, `/\`) {
		auth.WriteJSONError(w, http.StatusNotFound, "task not found")
		return
	}

	if len(parts) == 2 && parts[1] == "download" {
		logPath := s.store.GetRawLogPath(taskID)
		raw, err := os.ReadFile(logPath)
		if err != nil {
			auth.WriteJSONError(w, http.StatusNotFound, "Log file not found")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", taskID+".log"))
		_, _ = w.Write(raw)
		return
	}

	if len(parts) == 2 && parts[1] == "stream" {
		s.streamTaskLogsSSE(w, r, taskID)
		return
	}

	task, logs, err := s.store.GetTaskWithLogs(r.Context(), taskID)
	if err != nil {
		auth.WriteJSONError(w, http.StatusNotFound, "task not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"task": task,
		"logs": logs,
	})
}

func (s *Server) streamTaskLogsSSE(w http.ResponseWriter, r *http.Request, taskID string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		auth.WriteJSONError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	if _, _, err := s.store.GetTaskWithLogs(r.Context(), taskID); err != nil {
		auth.WriteJSONError(w, http.StatusNotFound, "task not found")
		return
	}

	ch, unsub := s.store.SubscribeTaskLogs(taskID)
	defer unsub()

	task, existingLogs, err := s.store.GetTaskWithLogs(r.Context(), taskID)
	if err != nil {
		auth.WriteJSONError(w, http.StatusNotFound, "task not found")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	lastSentSeq := 0
	for _, line := range existingLogs {
		raw, _ := json.Marshal(line)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", string(raw))
		if line.Seq > lastSentSeq {
			lastSentSeq = line.Seq
		}
	}
	flusher.Flush()

	if task.Status != "running" {
		_, _ = fmt.Fprintf(w, "event: done\ndata: %q\n\n", task.Status)
		flusher.Flush()
		return
	}

	shutCh := s.shutdownChan()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-shutCh:
			return
		case line, ok := <-ch:
			if !ok {
				curTask, _, _ := s.store.GetTaskWithLogs(r.Context(), taskID)
				status := "succeeded"
				if curTask != nil {
					status = curTask.Status
				}
				_, _ = fmt.Fprintf(w, "event: done\ndata: %q\n\n", status)
				flusher.Flush()
				return
			}
			if line.Seq <= lastSentSeq {
				continue
			}
			lastSentSeq = line.Seq
			raw, _ := json.Marshal(line)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", string(raw))
			flusher.Flush()
		}
	}
}
