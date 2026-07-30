package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/tmo/dscida/internal/store"
)

type Config struct {
	Store        *store.Store
	SessionID    string
	ServerName   string
	PollInterval time.Duration
	Input        io.Reader
	Output       io.Writer
	Log          io.Writer
}

type Server struct {
	config Config

	mu                sync.RWMutex
	instanceID        string
	downstream        *downstream
	tools             []json.RawMessage
	epoch             uint64
	generation        int
	clientInitialized bool
	terminalReplaced  bool
	pending           map[string]context.CancelFunc

	outputMu sync.Mutex
}

type upstreamMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func New(config Config) (*Server, error) {
	if config.Store == nil || config.Input == nil || config.Output == nil {
		return nil, fmt.Errorf("bridge store, input, and output are required")
	}
	if !store.ValidID(config.SessionID) || !store.ValidID(config.ServerName) {
		return nil, fmt.Errorf("invalid bridge session or server name")
	}
	session, err := config.Store.LoadSession(config.SessionID)
	if err != nil {
		return nil, err
	}
	if session.SchemaVersion != store.SessionSchemaVersion ||
		!store.ValidID(session.SessionInstanceID) {
		return nil, fmt.Errorf(
			"session %s must be resumed or recreated with schema v2 before --follow",
			config.SessionID,
		)
	}
	if config.PollInterval <= 0 {
		config.PollInterval = 500 * time.Millisecond
	}
	return &Server{
		config:     config,
		instanceID: session.SessionInstanceID,
		pending:    make(map[string]context.CancelFunc),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	watchContext, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.watch(watchContext)

	scanner := bufio.NewScanner(s.config.Input)
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	for scanner.Scan() {
		var message upstreamMessage
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			s.writeError(nil, -32700, "Parse error", nil)
			continue
		}
		s.handle(ctx, message)
	}
	s.clearDownstream(false)
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read upstream MCP stdio: %w", err)
	}
	return nil
}

func (s *Server) handle(ctx context.Context, message upstreamMessage) {
	hasID := len(message.ID) != 0 && string(message.ID) != "null"
	switch message.Method {
	case "initialize":
		if !hasID {
			return
		}
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if err := json.Unmarshal(message.Params, &params); err != nil {
			s.writeError(message.ID, -32602, "Invalid initialize params", nil)
			return
		}
		s.writeResult(message.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": true},
			},
			"serverInfo": map[string]string{
				"name": s.config.ServerName, "version": "0.2.0",
			},
			"instructions": fmt.Sprintf(
				"Stable dscida bridge bound to session %s.", s.config.SessionID,
			),
			"_meta": map[string]any{
				"session_id":          s.config.SessionID,
				"session_instance_id": s.instanceID,
				"requested_version":   params.ProtocolVersion,
			},
		})
	case "notifications/initialized":
		s.mu.Lock()
		s.clientInitialized = true
		s.mu.Unlock()
	case "notifications/cancelled":
		var params struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if json.Unmarshal(message.Params, &params) == nil {
			key := string(params.RequestID)
			s.mu.RLock()
			cancel := s.pending[key]
			s.mu.RUnlock()
			if cancel != nil {
				cancel()
			}
		}
	case "ping":
		if hasID {
			s.writeResult(message.ID, map[string]any{})
		}
	case "tools/list":
		if !hasID {
			return
		}
		s.mu.RLock()
		tools := cloneTools(s.tools)
		s.mu.RUnlock()
		s.writeResult(message.ID, map[string]any{"tools": tools})
	case "tools/call":
		if !hasID {
			return
		}
		s.startToolCall(ctx, message)
	default:
		if hasID {
			s.writeError(message.ID, -32601, "Method not found", nil)
		}
	}
}

func (s *Server) writeResult(id json.RawMessage, result any) {
	payload, _ := json.Marshal(result)
	s.writeRawResult(id, payload)
}

func (s *Server) writeRawResult(id, result json.RawMessage) {
	s.write(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func (s *Server) writeError(id json.RawMessage, code int, message string, data any) {
	detail := map[string]any{"code": code, "message": message}
	if data != nil {
		detail["data"] = data
	}
	s.write(map[string]any{"jsonrpc": "2.0", "id": id, "error": detail})
}

func (s *Server) writeRawError(id, rpcError json.RawMessage) {
	s.write(map[string]any{"jsonrpc": "2.0", "id": id, "error": rpcError})
}

func (s *Server) writeBridgeError(
	id json.RawMessage, number int, code string, retryable bool,
	generation int, epoch uint64,
) {
	s.writeError(id, number, code, map[string]any{
		"code":                code,
		"session_id":          s.config.SessionID,
		"session_instance_id": s.instanceID,
		"generation":          generation,
		"downstream_epoch":    epoch,
		"retryable":           retryable,
	})
}

func (s *Server) writeNotification(method string, params any) {
	message := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		message["params"] = params
	}
	s.write(message)
}

func (s *Server) write(message any) {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	encoder := json.NewEncoder(s.config.Output)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(message)
}

func (s *Server) logf(format string, values ...any) {
	if s.config.Log != nil {
		fmt.Fprintf(s.config.Log, format+"\n", values...)
	}
}

func cloneTools(tools []json.RawMessage) []json.RawMessage {
	cloned := make([]json.RawMessage, len(tools))
	for index, tool := range tools {
		cloned[index] = append(json.RawMessage(nil), tool...)
	}
	return cloned
}

func sameTools(first, second []json.RawMessage) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if string(first[index]) != string(second[index]) {
			return false
		}
	}
	return true
}
