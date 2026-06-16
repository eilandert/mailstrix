package yarad

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// FuzzScanBody throws arbitrary bytes at the /scan handler (the only
// attacker-reachable surface) through a fake engine, asserting the server never
// panics and always answers with a sane status. It guards the length/auth/read
// path against a regression that crashes on malformed input. Long fuzzing is
// local; CI runs a short smoke window (see .github/workflows/ci.yml).
func FuzzScanBody(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("x"))
	f.Add([]byte("PING\n\n"))
	f.Add(bytes.Repeat([]byte("A"), 4096))
	f.Add([]byte("$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"))

	s := newTestServer(&fakeEngine{matches: []Match{{Rule: "R"}}, count: 1, fp: "fz"}, "tok")
	f.Fuzz(func(t *testing.T, body []byte) {
		r := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
		r.Header.Set("Content-Length", strconv.Itoa(len(body)))
		r.Header.Set("X-YARAD-Token", "tok")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r) // must not panic
		switch w.Code {
		case http.StatusOK, http.StatusBadRequest, http.StatusServiceUnavailable, http.StatusUnauthorized:
		default:
			t.Fatalf("unexpected status %d for %d-byte body", w.Code, len(body))
		}
	})
}
