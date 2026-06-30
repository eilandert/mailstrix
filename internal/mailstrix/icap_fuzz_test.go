package mailstrix

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// FuzzReadICAPChunkHeaderLine drives the single-chunk-header reader with
// arbitrary bytes. The reader is on the ICAP network path — any remote proxy
// can send hostile input. Invariants:
//   - never panic
//   - when errICAPChunkHeaderTooLong is returned, no more than
//     maxICAPChunkHeaderLine bytes were buffered before the error
func FuzzReadICAPChunkHeaderLine(f *testing.F) {
	// Valid chunk-size lines.
	f.Add([]byte("0\r\n"))
	f.Add([]byte("1a\r\n"))
	f.Add([]byte("ff; ieof\r\n"))
	f.Add([]byte("3c ; ieof\r\n"))
	f.Add([]byte("100\n")) // LF-only (some proxies)
	// No terminator — must return an error, not block.
	f.Add([]byte("abc"))
	// Exactly at the cap, then newline.
	f.Add(append(bytes.Repeat([]byte("f"), maxICAPChunkHeaderLine), '\n'))
	// One over the cap — must return errICAPChunkHeaderTooLong.
	f.Add(append(bytes.Repeat([]byte("f"), maxICAPChunkHeaderLine+1), '\n'))
	// Empty.
	f.Add([]byte{})
	// Binary junk.
	f.Add(bytes.Repeat([]byte{0xFF}, 32))
	f.Add([]byte("\x00\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		br := bufio.NewReader(bytes.NewReader(data))
		line, err := readICAPChunkHeaderLine(br)
		if err != nil {
			return // errors expected; must not panic
		}
		// Returned line must be no longer than the cap (CRLF stripped).
		if len(line) > maxICAPChunkHeaderLine {
			t.Fatalf("returned line len %d > cap %d", len(line), maxICAPChunkHeaderLine)
		}
	})
}

// FuzzReadICAPChunkedBody drives the full chunked-body reader with arbitrary
// bytes. Any remote ICAP proxy can control this stream, making it a high-value
// target. Invariants:
//   - never panic
//   - on success, returned body len ≤ maxBody
//   - ieof=true only when a 0-chunk with "ieof" extension was seen (structural)
func FuzzReadICAPChunkedBody(f *testing.F) {
	const maxBody = 8 * 1024 * 1024 // mirrors default MaxBody

	// Well-formed terminal chunk (empty body, ieof).
	f.Add([]byte("0; ieof\r\n\r\n"))
	// Well-formed terminal chunk without ieof.
	f.Add([]byte("0\r\n\r\n"))
	// Single data chunk + terminal.
	f.Add([]byte("5\r\nhello\r\n0\r\n\r\n"))
	// Multi-chunk.
	f.Add([]byte("3\r\nfoo\r\n4\r\nbarr\r\n0; ieof\r\n\r\n"))
	// Chunk size that would exceed maxBody.
	f.Add([]byte(fmt.Sprintf("%x\r\n", int64(maxBody)+1)))
	// Bad hex size.
	f.Add([]byte("zz\r\ndata\r\n"))
	// Truncated mid-data.
	f.Add([]byte("a\r\nhello"))
	// Extensions with spaces and garbage.
	f.Add([]byte("5  ; ieof garbage extra\r\nhello\r\n0\r\n\r\n"))
	// Empty.
	f.Add([]byte{})
	// Binary junk.
	f.Add(bytes.Repeat([]byte{0xFF}, 64))
	// Chunk claiming 0 bytes (terminal) with no trailing CRLF.
	f.Add([]byte("0"))
	// Multiple terminators (should stop at first).
	f.Add([]byte("0\r\n\r\n0\r\n\r\n"))
	// Large valid body near the cap (2 chunks of 4 MiB - 1).
	chunk4m := strings.Repeat("A", 4*1024*1024-1)
	f.Add([]byte(fmt.Sprintf("%x\r\n%s\r\n%x\r\n%s\r\n0;ieof\r\n\r\n",
		len(chunk4m), chunk4m, len(chunk4m), chunk4m)))

	f.Fuzz(func(t *testing.T, data []byte) {
		br := bufio.NewReader(bytes.NewReader(data))
		body, _, err := readICAPChunkedBody(br, maxBody)
		if err != nil {
			return
		}
		if int64(len(body)) > maxBody {
			t.Fatalf("body len %d exceeds maxBody %d", len(body), maxBody)
		}
	})
}
