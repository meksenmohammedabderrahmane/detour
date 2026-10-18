//go:build windows

package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestIPC_RoundTrip(t *testing.T) {
	pipeName := fmt.Sprintf(`\\.\pipe\DetourTest_%d_%d`, os.Getpid(), time.Now().UnixNano())

	sid, _ := CurrentUserSID()
	l, err := Listen(pipeName, sid)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	srv := NewServer(l)
	srv.Handle("test.ping", func(params json.RawMessage) (interface{}, error) {
		var in map[string]string
		_ = json.Unmarshal(params, &in)
		return map[string]string{"reply": "pong-" + in["msg"]}, nil
	})

	go func() {
		_ = srv.Serve()
	}()
	defer srv.Stop()

	// Give server a moment to enter accept
	time.Sleep(50 * time.Millisecond)

	client := NewClient(pipeName)
	var res map[string]string
	err = client.Call("test.ping", map[string]string{"msg": "hello"}, &res)
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}
	if res["reply"] != "pong-hello" {
		t.Fatalf("want pong-hello, got %q", res["reply"])
	}

	// Unknown method error
	err = client.Call("unknown.method", nil, &res)
	if err == nil {
		t.Fatalf("expected error for unknown method, got nil")
	}
}

func TestIPC_NonBlockingBroadcast(t *testing.T) {
	pipeName := fmt.Sprintf(`\\.\pipe\DetourTest_Events_%d_%d`, os.Getpid(), time.Now().UnixNano())

	sid, _ := CurrentUserSID()
	l, err := Listen(pipeName, sid)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	srv := NewServer(l)
	go func() {
		_ = srv.Serve()
	}()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	// Connect subscriber
	client := NewClient(pipeName)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	received := make(chan Event, 100)
	go func() {
		_ = client.Subscribe(ctx, func(ev Event) {
			received <- ev
		})
	}()

	time.Sleep(50 * time.Millisecond)

	// Broadcast 100 events
	for i := 0; i < 100; i++ {
		srv.Broadcast(Event{
			Type: "test_counter",
			Data: map[string]int{"val": i},
		})
	}

	// Even if subscriber channel overflows or drops, server broadcast never stalls
	select {
	case ev := <-received:
		if ev.Type != "test_counter" {
			t.Fatalf("unexpected event type %q", ev.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for event")
	}
}
