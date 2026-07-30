package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/tmo/dscida/internal/control"
	"github.com/tmo/dscida/internal/runner"
	"github.com/tmo/dscida/internal/store"
)

func submitJob(ctx context.Context, session *store.Session, job *store.Job, route string) error {
	payload := map[string]any{
		"job_id": job.JobID, "request_id": job.RequestID,
		"payload_hash": job.PayloadHash, "base_generation": job.BaseGeneration,
	}
	if job.Operation == "add" {
		payload["module_path"] = job.ModulePath
		payload["image_index"] = *job.ImageIndex
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		var response map[string]any
		lastErr = control.New(session.ControlURL, session.ControlToken).Post(ctx, route, payload, &response, http.StatusAccepted)
		if lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(250 * time.Millisecond):
		}
	}
	return lastErr
}

func submissionOutcome(st *store.Store, job *store.Job, submitErr error) error {
	fresh, err := st.LoadJob(job.SessionID, job.JobID)
	if err != nil {
		return fmt.Errorf("submit job: %v; durable job unreadable: %w", submitErr, err)
	}
	*job = *fresh
	if fresh.State != "queued" {
		return nil
	}
	return fmt.Errorf(
		"job %s submission outcome is unknown after retries: %v; the durable queued job was retained, run `dscida wait %s` to retry safely",
		job.JobID, submitErr, job.JobID,
	)
}

func (e *environment) completeJob(ctx context.Context, st *store.Store, run *runner.Runner, session *store.Session, original *store.Job) (*store.Job, error) {
	return e.completeJobWithLifecycle(ctx, st, run, session, original, false)
}

func (e *environment) completeJobWithLifecycle(ctx context.Context, st *store.Store, run *runner.Runner, session *store.Session, original *store.Job, lifecycleHeld bool) (*store.Job, error) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		job, err := st.LoadJob(session.SessionID, original.JobID)
		if err != nil {
			return nil, err
		}
		switch job.State {
		case "validating":
			unlock, err := st.LockFinalizer(session.SessionID, job.JobID)
			if err != nil {
				return nil, err
			}
			job, err = st.LoadJob(session.SessionID, job.JobID)
			if err != nil {
				unlock()
				return nil, err
			}
			if job.State != "validating" {
				unlock()
				continue
			}
			if job.SnapshotPath == "" {
				unlock()
				return nil, e.failAndRecover(ctx, st, run, session, job, lifecycleHeld, fmt.Errorf("validating job has no snapshot path"))
			}
			expected, err := expectedIndexes(session, job)
			if err != nil {
				unlock()
				return nil, e.failAndRecover(ctx, st, run, session, job, lifecycleHeld, err)
			}
			observed, observationErr := validateObservedIndexes(job.LoadedImageIndexes, expected, session.ImageCount)
			if observationErr != nil {
				unlock()
				return nil, e.failAndRecover(ctx, st, run, session, job, lifecycleHeld, observationErr)
			}
			validation, err := run.Validate(
				ctx, st.SessionDir(session.SessionID), job.SnapshotPath, observed,
				session.ImageCount, session.DSCPath, session.DSCUUID, session.MainModule,
			)
			if err != nil {
				unlock()
				return nil, e.failAndRecover(ctx, st, run, session, job, lifecycleHeld, err)
			}
			if _, err := st.Commit(session, job, job.SnapshotPath, observed, validation.IDAVersion); err != nil {
				unlock()
				return nil, e.failAndRecover(ctx, st, run, session, job, lifecycleHeld, err)
			}
			unlock()
			return st.LoadJob(session.SessionID, job.JobID)
		case "succeeded":
			fresh, loadErr := st.LoadSession(session.SessionID)
			if loadErr != nil {
				return nil, loadErr
			}
			owns := ownsMutation(fresh, job.JobID)
			*session = *fresh
			if !owns {
				return job, nil
			}
			if err := st.ClearActiveJob(session, job.JobID, "ready"); err != nil {
				return nil, err
			}
			return job, nil
		case "failed", "interrupted_rolled_back", "outcome_unknown_live", "cancelled_before_start":
			fresh, loadErr := st.LoadSession(session.SessionID)
			if loadErr != nil {
				return nil, loadErr
			}
			owns := ownsMutation(fresh, job.JobID)
			*session = *fresh
			if !owns {
				return job, fmt.Errorf("historical job %s ended in %s: %s", job.JobID, job.State, job.Error)
			}
			return job, e.failAndRecover(ctx, st, run, session, job, lifecycleHeld, fmt.Errorf("job ended in %s: %s", job.State, job.Error))
		}
		select {
		case <-ctx.Done():
			return job, fmt.Errorf("wait timeout for job %s: %w; the job was not cancelled", job.JobID, ctx.Err())
		case <-ticker.C:
		}
	}
}
