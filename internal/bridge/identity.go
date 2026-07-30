package bridge

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/tmo/dscida/internal/control"
	"github.com/tmo/dscida/internal/store"
)

type controlStatus struct {
	Success           bool   `json:"success"`
	SchemaVersion     int    `json:"schema_version"`
	SessionID         string `json:"session_id"`
	SessionInstanceID string `json:"session_instance_id"`
	PID               int    `json:"pid"`
	DSCPath           string `json:"dsc_path"`
	DSCUUID           string `json:"dsc_uuid"`
	MainModule        string `json:"main_module"`
	IDA               struct {
		IDBPath string `json:"idb_path"`
	} `json:"ida"`
}

type healthResult struct {
	Status            string `json:"status"`
	IDBPath           string `json:"idb_path"`
	InputPath         string `json:"input_path"`
	AutoAnalysisReady bool   `json:"auto_analysis_ready"`
}

func verifyControlIdentity(ctx context.Context, session *store.Session) error {
	if session.State != "ready" || !store.ProcessAlive(session.IDAPID) {
		return fmt.Errorf("session is not ready")
	}
	if err := sameListener(session.ControlURL, session.MCPURL); err != nil {
		return err
	}
	client := control.New(session.ControlURL, session.ControlToken)
	var ping struct {
		Success bool `json:"success"`
		PID     int  `json:"pid"`
	}
	if err := client.Get(ctx, "/control/ping", &ping); err != nil {
		return fmt.Errorf("control ping: %w", err)
	}
	if !ping.Success || ping.PID != session.IDAPID {
		return fmt.Errorf("control ping PID mismatch")
	}
	var status controlStatus
	if err := client.Get(ctx, "/control/status", &status); err != nil {
		return fmt.Errorf("control status: %w", err)
	}
	if !status.Success || status.SchemaVersion != 2 ||
		status.SessionID != session.SessionID ||
		status.SessionInstanceID != session.SessionInstanceID ||
		status.PID != session.IDAPID ||
		status.DSCUUID != session.DSCUUID ||
		status.MainModule != session.MainModule ||
		!store.SamePath(status.DSCPath, session.DSCPath) ||
		!store.SamePath(status.IDA.IDBPath, session.WorkingIDBPath) {
		return fmt.Errorf("control status identity mismatch")
	}
	return nil
}

func verifyMCPIdentity(ctx context.Context, item *downstream, session *store.Session) error {
	health, err := item.serverHealth(ctx)
	if err != nil {
		return err
	}
	if !store.SamePath(health.IDBPath, session.WorkingIDBPath) ||
		!store.SamePath(health.InputPath, session.DSCPath) {
		return fmt.Errorf("MCP server_health identity mismatch")
	}
	return nil
}

func sameListener(controlURL, mcpURL string) error {
	controlEndpoint, err := url.Parse(controlURL)
	if err != nil {
		return err
	}
	mcpEndpoint, err := url.Parse(mcpURL)
	if err != nil {
		return err
	}
	if controlEndpoint.Scheme != mcpEndpoint.Scheme ||
		controlEndpoint.Hostname() != mcpEndpoint.Hostname() ||
		controlEndpoint.Port() != mcpEndpoint.Port() ||
		controlEndpoint.Path != "/control" ||
		mcpEndpoint.Path != "/mcp" {
		return fmt.Errorf("control and MCP endpoints do not share one canonical listener")
	}
	if controlEndpoint.Scheme != "http" ||
		!isLoopbackHost(controlEndpoint.Hostname()) {
		return fmt.Errorf("control and MCP listener must use HTTP on loopback")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
