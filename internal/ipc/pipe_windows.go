//go:build windows

package ipc

import (
	"fmt"
	"io"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const DefaultPipeName = `\\.\pipe\DetourControl`

type pipeConn struct {
	h    windows.Handle
	once sync.Once
}

func (c *pipeConn) Read(b []byte) (int, error) {
	var done uint32
	err := windows.ReadFile(c.h, b, &done, nil)
	if err != nil {
		if err == windows.ERROR_BROKEN_PIPE || err == windows.ERROR_PIPE_NOT_CONNECTED {
			return int(done), io.EOF
		}
		return int(done), err
	}
	return int(done), nil
}

func (c *pipeConn) Write(b []byte) (int, error) {
	var done uint32
	err := windows.WriteFile(c.h, b, &done, nil)
	return int(done), err
}

func (c *pipeConn) Close() error {
	var err error
	c.once.Do(func() {
		_ = windows.DisconnectNamedPipe(c.h)
		err = windows.CloseHandle(c.h)
	})
	return err
}

type clientConn struct {
	h    windows.Handle
	once sync.Once
}

func (c *clientConn) Read(b []byte) (int, error) {
	var done uint32
	err := windows.ReadFile(c.h, b, &done, nil)
	if err != nil {
		if err == windows.ERROR_BROKEN_PIPE || err == windows.ERROR_PIPE_NOT_CONNECTED {
			return int(done), io.EOF
		}
		return int(done), err
	}
	return int(done), nil
}

func (c *clientConn) Write(b []byte) (int, error) {
	var done uint32
	err := windows.WriteFile(c.h, b, &done, nil)
	return int(done), err
}

func (c *clientConn) Close() error {
	var err error
	c.once.Do(func() {
		err = windows.CloseHandle(c.h)
	})
	return err
}

// Listener is a Windows Named Pipe listener.
type Listener struct {
	name   string
	sa     *windows.SecurityAttributes
	closed bool
	mu     sync.Mutex
}

func Listen(name string, installingUserSID string) (*Listener, error) {
	if name == "" {
		name = DefaultPipeName
	}

	// SDDL: SYSTEM (SY), Built-in Administrators (BA), Owner (OW)
	// plus Installing User SID if present.
	sddl := "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"
	if installingUserSID != "" {
		sddl += fmt.Sprintf("(A;;GA;;;%s)", installingUserSID)
	}
	// WHY Mandatory Label S:(ML;;NW;;;ME): the service runs as SYSTEM in
	// Session 0 (System Integrity Level). Without a Medium Integrity (ME)
	// label in the SACL, Windows Mandatory Integrity Control (MIC) denies
	// write access to non-admin Medium Integrity processes in Session 1
	// regardless of the DACL.
	sddl += "S:(ML;;NW;;;ME)"

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build security descriptor from %q: %w", sddl, err)
	}

	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}

	return &Listener{name: name, sa: sa}, nil
}

func (l *Listener) Accept() (io.ReadWriteCloser, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, fmt.Errorf("listener closed")
	}
	l.mu.Unlock()

	namePtr, err := windows.UTF16PtrFromString(l.name)
	if err != nil {
		return nil, err
	}

	openMode := uint32(windows.PIPE_ACCESS_DUPLEX)
	pipeMode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | windows.PIPE_REJECT_REMOTE_CLIENTS)

	h, err := windows.CreateNamedPipe(
		namePtr,
		openMode,
		pipeMode,
		windows.PIPE_UNLIMITED_INSTANCES,
		64*1024, // 64K out buffer
		64*1024, // 64K in buffer
		0,       // default timeout
		l.sa,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateNamedPipe: %w", err)
	}

	err = windows.ConnectNamedPipe(h, nil)
	if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("ConnectNamedPipe: %w", err)
	}

	return &pipeConn{h: h}, nil
}

func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}

// Dial connects a client to the named pipe.
func Dial(pipePath string) (io.ReadWriteCloser, error) {
	if pipePath == "" {
		pipePath = DefaultPipeName
	}
	p, err := windows.UTF16PtrFromString(pipePath)
	if err != nil {
		return nil, err
	}

	h, err := windows.CreateFile(
		p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open pipe %s: %w", pipePath, err)
	}

	return &clientConn{h: h}, nil
}

// CurrentUserSID returns the string SID of the calling thread/process user.
func CurrentUserSID() (string, error) {
	var tok windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok)
	if err != nil {
		return "", err
	}
	defer tok.Close()

	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}
