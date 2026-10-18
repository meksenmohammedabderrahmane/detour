package ipc

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

type HandlerFunc func(params json.RawMessage) (interface{}, error)

type Server struct {
	l        *Listener
	handlers map[string]HandlerFunc
	mu       sync.RWMutex
	subsMu   sync.Mutex
	subs     map[uint64]chan Event
	subNext  uint64
	closed   bool
	done     chan struct{}
}

func NewServer(l *Listener) *Server {
	return &Server{
		l:        l,
		handlers: make(map[string]HandlerFunc),
		subs:     make(map[uint64]chan Event),
		done:     make(chan struct{}),
	}
}

func (s *Server) Handle(method string, h HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[method] = h
}

func (s *Server) Serve() error {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
				return err
			}
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn io.ReadWriteCloser) {
	defer conn.Close()

	for {
		var req Request
		if err := ReadMsg(conn, &req); err != nil {
			return
		}

		if req.Method == "events" {
			// Subscription request: stream events non-blockingly until client disconnects
			s.serveEvents(conn, req.ID)
			return
		}

		s.mu.RLock()
		h, ok := s.handlers[req.Method]
		s.mu.RUnlock()

		resp := Response{ID: req.ID}
		if !ok {
			resp.Error = fmt.Sprintf("method %q not found", req.Method)
		} else {
			res, err := h(req.Params)
			if err != nil {
				resp.Error = err.Error()
			} else {
				resp.Result = res
			}
		}

		if err := WriteMsg(conn, resp); err != nil {
			return
		}
	}
}

func (s *Server) serveEvents(conn io.ReadWriteCloser, reqID uint64) {
	ch := make(chan Event, 64) // buffered queue for subscriber

	s.subsMu.Lock()
	s.subNext++
	id := s.subNext
	s.subs[id] = ch
	s.subsMu.Unlock()

	defer func() {
		s.subsMu.Lock()
		delete(s.subs, id)
		s.subsMu.Unlock()
	}()

	// Initial confirmation response
	initResp := Response{ID: reqID, Result: map[string]bool{"subscribed": true}}
	if err := WriteMsg(conn, initResp); err != nil {
		return
	}

	// Stream events until write error or client closes
	for ev := range ch {
		if err := WriteMsg(conn, ev); err != nil {
			return
		}
	}
}

// Broadcast sends an event to all subscribed clients non-blockingly.
// A slow or dead client will drop events from its buffer and never block the engine.
func (s *Server) Broadcast(ev Event) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()

	for _, ch := range s.subs {
		select {
		case ch <- ev:
		default:
			// Client buffer full: drop event non-blockingly
		}
	}
}

func (s *Server) Stop() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.done)
	s.mu.Unlock()

	s.subsMu.Lock()
	for _, ch := range s.subs {
		close(ch)
	}
	s.subs = make(map[uint64]chan Event)
	s.subsMu.Unlock()

	return s.l.Close()
}
