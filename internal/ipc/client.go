package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

type Client struct {
	pipePath string
	mu       sync.Mutex
	conn     io.ReadWriteCloser
	reqID    uint64
}

func NewClient(pipePath string) *Client {
	if pipePath == "" {
		pipePath = DefaultPipeName
	}
	return &Client{pipePath: pipePath}
}

func (c *Client) Call(method string, params interface{}, result interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := Dial(c.pipePath)
	if err != nil {
		return fmt.Errorf("connect to service at %s: %w", c.pipePath, err)
	}
	defer conn.Close()

	var rawParams json.RawMessage
	if params != nil {
		pData, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("marshal params: %w", err)
		}
		rawParams = pData
	}

	id := atomic.AddUint64(&c.reqID, 1)
	req := Request{
		ID:     id,
		Method: method,
		Params: rawParams,
	}

	if err := WriteMsg(conn, req); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	var resp Response
	if err := ReadMsg(conn, &resp); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.Error != "" {
		return errors.New(resp.Error)
	}

	if result != nil && resp.Result != nil {
		resBytes, err := json.Marshal(resp.Result)
		if err != nil {
			return fmt.Errorf("re-marshal result: %w", err)
		}
		if err := json.Unmarshal(resBytes, result); err != nil {
			return fmt.Errorf("unmarshal result: %w", err)
		}
	}
	return nil
}

// Subscribe streams events until ctx is done or connection drops.
func (c *Client) Subscribe(ctx context.Context, onEvent func(Event)) error {
	conn, err := Dial(c.pipePath)
	if err != nil {
		return fmt.Errorf("connect to service: %w", err)
	}
	defer conn.Close()

	// Send subscription request
	req := Request{
		ID:     1,
		Method: "events",
	}
	if err := WriteMsg(conn, req); err != nil {
		return fmt.Errorf("send subscribe: %w", err)
	}

	// Read initial subscription response
	var initResp Response
	if err := ReadMsg(conn, &initResp); err != nil {
		return fmt.Errorf("read subscribe response: %w", err)
	}
	if initResp.Error != "" {
		return errors.New(initResp.Error)
	}

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	for {
		var ev Event
		if err := ReadMsg(conn, &ev); err != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			return err
		}
		onEvent(ev)
	}
}
