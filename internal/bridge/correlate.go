package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tmo/dscida/internal/store"
)

func (s *Server) startToolCall(parent context.Context, message upstreamMessage) {
	callContext, cancel := context.WithCancel(parent)
	key := string(message.ID)
	s.mu.Lock()
	if _, exists := s.pending[key]; exists {
		s.mu.Unlock()
		cancel()
		s.writeError(message.ID, -32600, "Duplicate pending request ID", nil)
		return
	}
	s.pending[key] = cancel
	s.mu.Unlock()
	go s.forwardToolCall(callContext, message, key, cancel)
}

func (s *Server) forwardToolCall(
	callContext context.Context, message upstreamMessage,
	key string, cancel context.CancelFunc,
) {
	defer func() {
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
		cancel()
	}()
	s.mu.RLock()
	item := s.downstream
	epoch := s.epoch
	generation := s.generation
	replaced := s.terminalReplaced
	s.mu.RUnlock()
	if replaced {
		s.writeBridgeError(
			message.ID, -32064, "dscida_session_replaced", false, generation, epoch,
		)
		return
	}
	if item == nil {
		s.writeBridgeError(
			message.ID, -32061, "dscida_instance_unavailable", true, generation, epoch,
		)
		return
	}
	preflightContext, preflightCancel := context.WithTimeout(callContext, 5*time.Second)
	preflightCode, preflightErr := s.preflight(preflightContext, item)
	preflightCancel()
	if preflightErr != nil {
		if callContext.Err() != nil {
			s.writeError(message.ID, -32800, "Request cancelled", map[string]any{
				"code": "dscida_request_cancelled",
			})
			return
		}
		number := -32062
		retryable := true
		switch preflightCode {
		case "dscida_instance_unavailable":
			number = -32061
		case "dscida_session_replaced":
			number, retryable = -32064, false
		}
		s.writeBridgeError(
			message.ID, number, preflightCode, retryable, generation, epoch,
		)
		return
	}
	if callContext.Err() != nil {
		s.writeError(message.ID, -32800, "Request cancelled", map[string]any{
			"code": "dscida_request_cancelled",
		})
		return
	}
	var params any
	if err := json.Unmarshal(message.Params, &params); err != nil {
		s.writeError(message.ID, -32602, "Invalid tools/call params", nil)
		return
	}
	result, rpcError, err := item.call(callContext, "tools/call", params)
	if err == nil {
		if len(rpcError) != 0 {
			s.writeRawError(message.ID, rpcError)
		} else {
			s.writeRawResult(message.ID, result)
		}
		return
	}
	if callContext.Err() != nil {
		s.writeError(message.ID, -32800, "Request cancelled", map[string]any{
			"code": "dscida_request_cancelled",
		})
		return
	}
	s.mu.RLock()
	current := s.downstream
	currentEpoch := s.epoch
	currentGeneration := s.generation
	terminal := s.terminalReplaced
	s.mu.RUnlock()
	if terminal {
		s.writeBridgeError(
			message.ID, -32064, "dscida_session_replaced", false,
			currentGeneration, currentEpoch,
		)
		return
	}
	if current != item || currentEpoch != epoch {
		s.writeBridgeError(
			message.ID, -32063, "dscida_instance_restarted", true,
			currentGeneration, currentEpoch,
		)
		return
	}
	if errors.Is(err, errDownstreamSessionInvalid) {
		s.clearSpecificDownstream(item)
	}
	s.writeBridgeError(
		message.ID, -32061, "dscida_instance_unavailable", true,
		currentGeneration, currentEpoch,
	)
}

func (s *Server) preflight(ctx context.Context, item *downstream) (string, error) {
	session, err := s.config.Store.LoadSession(s.config.SessionID)
	if err != nil {
		return "dscida_instance_identity_mismatch", err
	}
	if session.SessionInstanceID != s.instanceID {
		s.mu.Lock()
		s.terminalReplaced = true
		s.mu.Unlock()
		s.clearSpecificDownstream(item)
		return "dscida_session_replaced", fmt.Errorf("session instance changed")
	}
	if session.State != "ready" || !store.ProcessAlive(session.IDAPID) ||
		session.IDAPID != item.pid || session.MCPURL != item.endpoint {
		s.clearSpecificDownstream(item)
		return "dscida_instance_unavailable", fmt.Errorf("session endpoint changed")
	}
	if err := verifyControlIdentity(ctx, session); err != nil {
		if ctx.Err() != nil {
			return "dscida_instance_unavailable", ctx.Err()
		}
		s.clearSpecificDownstream(item)
		s.logf(
			"mcp_bridge_identity_mismatch session=%s error=%q",
			s.config.SessionID, err,
		)
		return "dscida_instance_identity_mismatch", err
	}
	return "", nil
}
