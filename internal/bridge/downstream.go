package bridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const protocolVersion = "2025-06-18"

var errDownstreamSessionInvalid = errors.New("downstream MCP session invalid")

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type downstream struct {
	endpoint   string
	sessionID  string
	client     *http.Client
	ctx        context.Context
	cancel     context.CancelFunc
	nextID     atomic.Uint64
	pid        int
	gate       chan struct{}
	toolChange chan struct{}
}

func newDownstream(ctx context.Context, endpoint string) (*downstream, error) {
	epochContext, cancel := context.WithCancel(ctx)
	item := &downstream{
		endpoint:   endpoint,
		client:     noRedirectHTTPClient(),
		ctx:        epochContext,
		cancel:     cancel,
		gate:       make(chan struct{}, 1),
		toolChange: make(chan struct{}, 1),
	}
	params := map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]string{
			"name": "dscida-bridge", "version": "0.2.0",
		},
	}
	initializeContext, initializeCancel := context.WithTimeout(epochContext, 15*time.Second)
	defer initializeCancel()
	response, headers, err := item.post(initializeContext, "initialize", params, false)
	if err != nil {
		cancel()
		return nil, err
	}
	if len(response.Error) != 0 {
		cancel()
		return nil, fmt.Errorf("downstream initialize error: %s", response.Error)
	}
	var initialized struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(response.Result, &initialized); err != nil {
		cancel()
		return nil, fmt.Errorf("decode downstream initialize: %w", err)
	}
	if initialized.ProtocolVersion != protocolVersion {
		cancel()
		return nil, fmt.Errorf(
			"downstream negotiated unsupported MCP version %q",
			initialized.ProtocolVersion,
		)
	}
	item.sessionID = headers.Get("Mcp-Session-Id")
	if err := item.notify(initializeContext, "notifications/initialized", map[string]any{}); err != nil {
		cancel()
		return nil, fmt.Errorf("send downstream initialized notification: %w", err)
	}
	go item.listen(epochContext)
	return item, nil
}

func (d *downstream) close() {
	d.cancel()
	if d.sessionID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, d.endpoint, nil)
	if err != nil {
		return
	}
	d.setHeaders(request)
	response, err := d.client.Do(request)
	if err == nil {
		response.Body.Close()
	}
}

func (d *downstream) call(
	ctx context.Context, method string, params any,
) (json.RawMessage, json.RawMessage, error) {
	select {
	case d.gate <- struct{}{}:
		defer func() { <-d.gate }()
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-d.ctx.Done():
		return nil, nil, d.ctx.Err()
	}
	callContext, cancel := context.WithCancel(d.ctx)
	id := d.nextID.Add(1)
	var cancellationMu sync.Mutex
	completed := false
	stop := context.AfterFunc(ctx, func() {
		cancellationMu.Lock()
		defer cancellationMu.Unlock()
		if completed {
			return
		}
		cancel()
		notifyContext, notifyCancel := context.WithTimeout(d.ctx, 2*time.Second)
		defer notifyCancel()
		_ = d.notify(notifyContext, "notifications/cancelled", map[string]any{
			"requestId": id, "reason": "upstream request cancelled",
		})
	})
	defer func() {
		cancellationMu.Lock()
		completed = true
		cancellationMu.Unlock()
		stop()
		cancel()
	}()
	response, _, err := d.postWithID(callContext, id, method, params, true)
	if err != nil {
		return nil, nil, err
	}
	return response.Result, response.Error, nil
}

func (d *downstream) takeToolChange() bool {
	select {
	case <-d.toolChange:
		return true
	default:
		return false
	}
}

func (d *downstream) listen(ctx context.Context) {
	for {
		if err := d.listenOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			timer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		return
	}
}

func (d *downstream) listenOnce(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, d.endpoint, nil)
	if err != nil {
		return err
	}
	d.setHeaders(request)
	request.Header.Del("Content-Type")
	request.Header.Set("Accept", "text/event-stream")
	response, err := d.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusMethodNotAllowed ||
		response.StatusCode == http.StatusNotFound {
		return nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("downstream SSE GET HTTP %d", response.StatusCode)
	}
	scanner := bufio.NewScanner(io.LimitReader(response.Body, 64<<20))
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var message rpcResponse
		if json.Unmarshal(
			[]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))),
			&message,
		) == nil && message.Method == "notifications/tools/list_changed" {
			select {
			case d.toolChange <- struct{}{}:
			default:
			}
		}
	}
	return scanner.Err()
}

func (d *downstream) tools(ctx context.Context) ([]json.RawMessage, error) {
	var tools []json.RawMessage
	cursor := ""
	seen := make(map[string]bool)
	for {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		result, rpcError, err := d.call(ctx, "tools/list", params)
		if err != nil {
			return nil, err
		}
		if len(rpcError) != 0 {
			return nil, fmt.Errorf("downstream tools/list error: %s", rpcError)
		}
		var list struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}
		if err := json.Unmarshal(result, &list); err != nil {
			return nil, fmt.Errorf("decode downstream tools/list: %w", err)
		}
		tools = append(tools, list.Tools...)
		if list.NextCursor == "" {
			return tools, nil
		}
		if seen[list.NextCursor] {
			return nil, fmt.Errorf("downstream tools/list repeated cursor")
		}
		seen[list.NextCursor] = true
		cursor = list.NextCursor
	}
}

func (d *downstream) serverHealth(ctx context.Context) (*healthResult, error) {
	result, rpcError, err := d.call(ctx, "tools/call", map[string]any{
		"name": "server_health", "arguments": map[string]any{},
	})
	if err != nil {
		return nil, err
	}
	if len(rpcError) != 0 {
		return nil, fmt.Errorf("downstream server_health error: %s", rpcError)
	}
	var envelope struct {
		Structured healthResult `json:"structuredContent"`
		IsError    bool         `json:"isError"`
	}
	if err := json.Unmarshal(result, &envelope); err != nil {
		return nil, fmt.Errorf("decode downstream server_health: %w", err)
	}
	if envelope.IsError || envelope.Structured.Status != "ok" {
		return nil, fmt.Errorf("downstream server_health did not report ok")
	}
	return &envelope.Structured, nil
}

func (d *downstream) notify(ctx context.Context, method string, params any) error {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "method": method, "params": params,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, d.endpoint, bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	d.setHeaders(request)
	response, err := d.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound && d.sessionID != "" {
		return errDownstreamSessionInvalid
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		return fmt.Errorf("downstream notification HTTP %d: %s", response.StatusCode, payload)
	}
	return nil
}

func (d *downstream) post(
	ctx context.Context, method string, params any, established bool,
) (*rpcResponse, http.Header, error) {
	id := d.nextID.Add(1)
	return d.postWithID(ctx, id, method, params, established)
}

func (d *downstream) postWithID(
	ctx context.Context, id uint64, method string, params any, established bool,
) (*rpcResponse, http.Header, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": method, "params": params,
	})
	if err != nil {
		return nil, nil, err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, d.endpoint, bytes.NewReader(body),
	)
	if err != nil {
		return nil, nil, err
	}
	d.setHeaders(request)
	if !established {
		request.Header.Del("Mcp-Session-Id")
		request.Header.Del("MCP-Protocol-Version")
	}
	response, err := d.client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound && established && d.sessionID != "" {
		return nil, response.Header, errDownstreamSessionInvalid
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 4<<20))
		return nil, response.Header, fmt.Errorf(
			"downstream MCP HTTP %d: %s", response.StatusCode, payload,
		)
	}
	decoded, err := decodeRPCResponse(response, id, d.toolChange)
	if err != nil {
		return nil, response.Header, err
	}
	return decoded, response.Header, nil
}

func (d *downstream) setHeaders(request *http.Request) {
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", protocolVersion)
	if d.sessionID != "" {
		request.Header.Set("Mcp-Session-Id", d.sessionID)
	}
}

func noRedirectHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(
			request *http.Request, via []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}
}

func decodeRPCResponse(
	response *http.Response, expectedID uint64, toolChange chan<- struct{},
) (*rpcResponse, error) {
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaType != "text/event-stream" {
		var decoded rpcResponse
		decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<20))
		if err := decoder.Decode(&decoded); err != nil {
			return nil, fmt.Errorf("decode downstream JSON response: %w", err)
		}
		if string(decoded.ID) != strconv.FormatUint(expectedID, 10) {
			return nil, fmt.Errorf("downstream JSON response ID mismatch")
		}
		return &decoded, nil
	}
	scanner := bufio.NewScanner(io.LimitReader(response.Body, 16<<20))
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var decoded rpcResponse
		if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &decoded); err != nil {
			return nil, fmt.Errorf("decode downstream SSE response: %w", err)
		}
		if decoded.Method == "notifications/tools/list_changed" {
			select {
			case toolChange <- struct{}{}:
			default:
			}
			continue
		}
		if string(decoded.ID) == strconv.FormatUint(expectedID, 10) {
			return &decoded, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("downstream SSE response contained no JSON-RPC message")
}
