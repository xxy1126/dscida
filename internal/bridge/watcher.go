package bridge

import (
	"context"
	"time"

	"github.com/tmo/dscida/internal/store"
)

func (s *Server) watch(ctx context.Context) {
	s.refresh(ctx)
	ticker := time.NewTicker(s.config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refresh(ctx)
		}
	}
}

func (s *Server) refresh(ctx context.Context) {
	s.mu.RLock()
	terminal := s.terminalReplaced
	s.mu.RUnlock()
	if terminal {
		return
	}
	session, err := s.config.Store.LoadSession(s.config.SessionID)
	if err != nil {
		s.clearDownstream(true)
		return
	}
	if session.SessionInstanceID != s.instanceID {
		s.mu.Lock()
		s.terminalReplaced = true
		s.mu.Unlock()
		s.clearDownstream(true)
		s.logf("mcp_bridge_session_replaced session=%s", s.config.SessionID)
		return
	}
	s.mu.RLock()
	current := s.downstream
	same := current != nil && current.endpoint == session.MCPURL &&
		current.pid == session.IDAPID
	s.mu.RUnlock()
	if same && session.State == "ready" && store.ProcessAlive(session.IDAPID) {
		if current.takeToolChange() {
			s.refreshToolSnapshot(ctx, current, session)
		}
		return
	}
	if session.State != "ready" || !store.ProcessAlive(session.IDAPID) ||
		session.MCPURL == "" || session.ControlURL == "" {
		s.clearDownstream(true)
		return
	}
	verifyContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := verifyControlIdentity(verifyContext, session); err != nil {
		s.logf("mcp_bridge_identity_mismatch session=%s error=%q", s.config.SessionID, err)
		s.clearDownstream(true)
		return
	}
	candidate, err := newDownstream(ctx, session.MCPURL)
	if err != nil {
		s.logf("mcp_bridge_downstream_lost session=%s error=%q", s.config.SessionID, err)
		s.clearDownstream(true)
		return
	}
	if err := verifyMCPIdentity(verifyContext, candidate, session); err != nil {
		candidate.close()
		s.logf("mcp_bridge_identity_mismatch session=%s error=%q", s.config.SessionID, err)
		s.clearDownstream(true)
		return
	}
	tools, err := candidate.tools(verifyContext)
	if err != nil {
		candidate.close()
		s.clearDownstream(true)
		return
	}
	candidate.pid = session.IDAPID
	s.mu.Lock()
	old := s.downstream
	changed := old == nil || !sameTools(s.tools, tools)
	s.epoch++
	s.generation = session.CurrentGeneration
	s.downstream = candidate
	s.tools = cloneTools(tools)
	initialized := s.clientInitialized
	epoch := s.epoch
	s.mu.Unlock()
	if old != nil {
		old.close()
	}
	if changed && initialized {
		s.writeNotification("notifications/tools/list_changed", nil)
	}
	s.logf(
		"mcp_bridge_downstream_ready session=%s epoch=%d endpoint=%s",
		s.config.SessionID, epoch, session.MCPURL,
	)
}

func (s *Server) refreshToolSnapshot(
	ctx context.Context, item *downstream, session *store.Session,
) {
	verifyContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := verifyControlIdentity(verifyContext, session); err != nil {
		s.clearSpecificDownstream(item)
		return
	}
	if err := verifyMCPIdentity(verifyContext, item, session); err != nil {
		s.clearSpecificDownstream(item)
		return
	}
	tools, err := item.tools(verifyContext)
	if err != nil {
		s.clearSpecificDownstream(item)
		return
	}
	s.mu.Lock()
	if s.downstream != item {
		s.mu.Unlock()
		return
	}
	s.tools = cloneTools(tools)
	initialized := s.clientInitialized
	s.mu.Unlock()
	if initialized {
		s.writeNotification("notifications/tools/list_changed", nil)
	}
	s.logf(
		"mcp_bridge_tools_refreshed session=%s count=%d",
		s.config.SessionID, len(tools),
	)
}

func (s *Server) clearSpecificDownstream(item *downstream) {
	s.mu.Lock()
	if s.downstream != item {
		s.mu.Unlock()
		return
	}
	hadTools := len(s.tools) != 0
	s.downstream = nil
	s.tools = nil
	s.epoch++
	initialized := s.clientInitialized
	s.mu.Unlock()
	item.close()
	if hadTools && initialized {
		s.writeNotification("notifications/tools/list_changed", nil)
	}
}

func (s *Server) clearDownstream(notify bool) {
	s.mu.Lock()
	old := s.downstream
	hadTools := len(s.tools) != 0
	s.downstream = nil
	s.tools = nil
	if old != nil {
		s.epoch++
	}
	initialized := s.clientInitialized
	s.mu.Unlock()
	if old != nil {
		old.close()
	}
	if notify && hadTools && initialized {
		s.writeNotification("notifications/tools/list_changed", nil)
	}
}
