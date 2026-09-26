package utils

import "sync"

// capBuffer is a bytes.Buffer that stops accumulating past a limit instead of
// growing without bound. A misbehaving or hostile tool cannot exhaust the
// server's memory by emitting gigabytes of output, and the caller is told that
// the tail was discarded so it can report the truncation honestly.
type capBuffer struct {
	mu       sync.Mutex
	buf      []byte
	limit    int
	overflow bool
}

func newCapBuffer(limit int) *capBuffer {
	if limit <= 0 {
		limit = 1 << 20
	}
	return &capBuffer{limit: limit, buf: make([]byte, 0, 4096)}
}

func (c *capBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.buf) >= c.limit {
		c.overflow = true
		// Report a full write so the child never blocks or sees EPIPE.
		return len(p), nil
	}
	remaining := c.limit - len(c.buf)
	if len(p) > remaining {
		c.buf = append(c.buf, p[:remaining]...)
		c.overflow = true
		return len(p), nil
	}
	c.buf = append(c.buf, p...)
	return len(p), nil
}

func (c *capBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.buf)
}

func (c *capBuffer) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.overflow
}
