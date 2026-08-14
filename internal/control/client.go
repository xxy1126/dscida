package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func New(baseURL, token string) *Client {
	baseURL = strings.TrimRight(baseURL, "/")
	baseURL = strings.TrimSuffix(baseURL, "/control")
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTP:    safeHTTPClient(10 * time.Second),
	}
}

func (c *Client) Get(ctx context.Context, route string, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+route, nil)
	if err != nil {
		return err
	}
	return c.do(request, output, http.StatusOK)
}

func (c *Client) Post(ctx context.Context, route string, input, output any, expected int) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+route, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	return c.do(request, output, expected)
}

// ExecPython runs a script on the IDA main thread. HTTP 200 means the script
// completed (success may still be false on a script error); HTTP 408 means the
// best-effort timeout fired and the result carries timed_out=true.
func (c *Client) ExecPython(ctx context.Context, script string, args map[string]string, timeoutMs int) (*ExecResult, error) {
	payload := map[string]any{"script": script}
	if args != nil {
		payload["args"] = args
	}
	if timeoutMs > 0 {
		payload["timeout_ms"] = timeoutMs
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/control/exec-python", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.Token)
	response, err := c.HTTP.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var result ExecResult
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("decode exec-python response: %w", err)
	}
	switch response.StatusCode {
	case http.StatusOK:
		return &result, nil
	case http.StatusRequestTimeout:
		result.TimedOut = true
		if result.Error == "" {
			result.Error = "exec timeout"
		}
		return &result, nil
	default:
		return nil, fmt.Errorf("control HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
}

type ExecResult struct {
	Success           bool            `json:"success"`
	SessionID         string          `json:"session_id"`
	SessionInstanceID string          `json:"session_instance_id"`
	PID               int             `json:"pid"`
	Stdout            string          `json:"stdout"`
	Result            json.RawMessage `json:"result"`
	Error             string          `json:"error"`
	Traceback         string          `json:"traceback"`
	ExecutionMS       float64         `json:"execution_ms"`
	TimedOut          bool            `json:"timed_out"`
}

// ResultValue decodes the opaque result field, or returns nil when absent.
func (r *ExecResult) ResultValue() (any, error) {
	if len(r.Result) == 0 || string(r.Result) == "null" {
		return nil, nil
	}
	var value any
	if err := json.Unmarshal(r.Result, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func (c *Client) do(request *http.Request, output any, expected int) error {
	request.Header.Set("Authorization", "Bearer "+c.Token)
	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != expected {
		return fmt.Errorf("control HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	if output != nil && len(body) > 0 {
		if err := json.Unmarshal(body, output); err != nil {
			return fmt.Errorf("decode control response: %w", err)
		}
	}
	return nil
}

func MCPHealth(ctx context.Context, endpoint string) error {
	sessionID, client, err := initializeMCP(ctx, endpoint)
	if err != nil {
		return err
	}
	toolsList := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(toolsList))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Mcp-Session-Id", sessionID)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("MCP tools/list: %w", err)
	}
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	response.Body.Close()
	if readErr != nil {
		return fmt.Errorf("read MCP tools/list: %w", readErr)
	}
	if response.StatusCode != http.StatusOK || !bytes.Contains(payload, []byte(`"tools"`)) || !bytes.Contains(payload, []byte(`"server_health"`)) {
		return fmt.Errorf("MCP tools/list health check failed (HTTP %d): %s", response.StatusCode, payload)
	}
	return nil
}

type ServerHealth struct {
	Status            string `json:"status"`
	IDBPath           string `json:"idb_path"`
	InputPath         string `json:"input_path"`
	AutoAnalysisReady bool   `json:"auto_analysis_ready"`
	HexRaysReady      bool   `json:"hexrays_ready"`
}

func MCPServerHealth(ctx context.Context, endpoint string) (*ServerHealth, error) {
	sessionID, client, err := initializeMCP(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	call := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"server_health","arguments":{}}}`)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(call))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Mcp-Session-Id", sessionID)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("MCP server_health: %w", err)
	}
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	response.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read MCP server_health: %w", readErr)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MCP server_health HTTP %d: %s", response.StatusCode, payload)
	}
	var envelope struct {
		Result struct {
			StructuredContent ServerHealth `json:"structuredContent"`
			IsError           bool         `json:"isError"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("decode MCP server_health: %w", err)
	}
	if len(envelope.Error) > 0 || envelope.Result.IsError || envelope.Result.StructuredContent.Status != "ok" {
		return nil, fmt.Errorf("MCP server_health returned failure: %s", payload)
	}
	return &envelope.Result.StructuredContent, nil
}

func initializeMCP(ctx context.Context, endpoint string) (string, *http.Client, error) {
	initialize := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]string{"name": "dscida", "version": "0.1.0"},
		},
	}
	body, _ := json.Marshal(initialize)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	client := safeHTTPClient(10 * time.Second)
	response, err := client.Do(request)
	if err != nil {
		return "", nil, fmt.Errorf("MCP initialize: %w", err)
	}
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	response.Body.Close()
	if readErr != nil {
		return "", nil, fmt.Errorf("read MCP initialize: %w", readErr)
	}
	if response.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("MCP initialize HTTP %d: %s", response.StatusCode, payload)
	}
	sessionID := response.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		return "", nil, fmt.Errorf("MCP initialize did not return Mcp-Session-Id")
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil || len(envelope.Result) == 0 || len(envelope.Error) > 0 {
		return "", nil, fmt.Errorf("invalid MCP initialize response: %s", payload)
	}
	return sessionID, client, nil
}

func safeHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(
			request *http.Request, via []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}
}
