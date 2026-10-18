package ipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Request is a JSON-RPC request.
type Request struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC response.
type Response struct {
	ID     uint64      `json:"id"`
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// Event is an asynchronous server push event.
type Event struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

const maxMessageSize = 16 * 1024 * 1024 // 16 MB max payload

// WriteMsg writes a length-prefixed JSON message.
func WriteMsg(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	if len(data) > maxMessageSize {
		return fmt.Errorf("message too large: %d > %d", len(data), maxMessageSize)
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ReadMsg reads a length-prefixed JSON message.
func ReadMsg(r io.Reader, v interface{}) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxMessageSize {
		return fmt.Errorf("message too large: %d > %d", n, maxMessageSize)
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}
