package extract

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// TestUndefang verifies individual substitution markers and the no-op contract.
func TestUndefang(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		want    string
		changed bool
	}{
		{
			name:    "hxxp bracketed dot",
			input:   "hxxp://evil[.]com/payload",
			want:    "http://evil.com/payload",
			changed: true,
		},
		{
			name:    "hxxps bracketed dot",
			input:   "hxxps://evil[.]com",
			want:    "https://evil.com",
			changed: true,
		},
		{
			name:    "HXXP uppercase",
			input:   "HXXP://evil[.]com",
			want:    "http://evil.com",
			changed: true,
		},
		{
			name:    "fxp scheme",
			input:   "fxp://files[.]example[.]com/drop",
			want:    "ftp://files.example.com/drop",
			changed: true,
		},
		{
			name:    "bracketed dot IP",
			input:   "1[.]2[.]3[.]4",
			want:    "1.2.3.4",
			changed: true,
		},
		{
			name:    "parenthesized dot",
			input:   "evil(.)com",
			want:    "evil.com",
			changed: true,
		},
		{
			name:    "bracketed dot keyword",
			input:   "evil[dot]com",
			want:    "evil.com",
			changed: true,
		},
		{
			name:    "parenthesized dot keyword",
			input:   "evil(dot)com",
			want:    "evil.com",
			changed: true,
		},
		{
			name:    "mailto bracketed colon and at",
			input:   "mailto[:]a[@]b[.]example[.]com",
			want:    "mailto:a@b.example.com",
			changed: true,
		},
		{
			name:    "parenthesized at",
			input:   "user(@)example.com",
			want:    "user@example.com",
			changed: true,
		},
		{
			name:    "bracketed at-word",
			input:   "user[at]example[.]com",
			want:    "user@example.com",
			changed: true,
		},
		{
			name:    "parenthesized at-word",
			input:   "user(at)example[.]com",
			want:    "user@example.com",
			changed: true,
		},
		{
			name:    "bracketed slash pair",
			input:   "http[://]evil.com",
			want:    "http://evil.com",
			changed: true,
		},
		{
			name:    "h[tt]p style",
			input:   "h[tt]p://evil.com",
			want:    "http://evil.com",
			changed: true,
		},
		{
			name:    "h[tt]ps style",
			input:   "h[tt]ps://evil.com",
			want:    "https://evil.com",
			changed: true,
		},
		{
			name:    "unchanged benign string returns false",
			input:   "this is normal text with no defang markers",
			want:    "this is normal text with no defang markers",
			changed: false,
		},
		{
			name:    "unchanged URL with real dot",
			input:   "http://example.com/path",
			want:    "http://example.com/path",
			changed: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			changed: false,
		},
		{
			name:    "braced dot",
			input:   "evil{.}com",
			want:    "evil.com",
			changed: true,
		},
		{
			name:    "hxxp with bracketed colon",
			input:   "hxxp[:]//evil[.]com",
			want:    "http://evil.com",
			changed: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := undefang([]byte(tc.input))
			if ok != tc.changed {
				t.Errorf("undefang(%q) changed=%v, want %v", tc.input, ok, tc.changed)
			}
			if string(got) != tc.want {
				t.Errorf("undefang(%q)\n  got  %q\n  want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestUndefangIdempotent verifies that applying undefang twice gives the same
// result as applying it once (the second call must be a no-op).
func TestUndefangIdempotent(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"hxxp://evil[.]com/payload",
		"1[.]2[.]3[.]4",
		"mailto[:]user[@]example[.]com",
		"h[tt]ps://malware[.]example[.]org/drop",
	}
	for _, in := range inputs {
		first, _ := undefang([]byte(in))
		second, changed2 := undefang(first)
		if changed2 {
			t.Errorf("idempotence violated for %q: second undefang changed %q → %q", in, first, second)
		}
		if string(second) != string(first) {
			t.Errorf("idempotence violated for %q: first=%q second=%q", in, first, second)
		}
	}
}

// TestFromEncodedDefangPath exercises the MSD-4 wiring: a buffer containing a
// defanged URL (long enough to clear minDecodedLen) must produce a stream that
// contains the un-defanged cleartext.
func TestFromEncodedDefangPath(t *testing.T) {
	t.Parallel()

	// Build a payload that is clearly text, clears minDecodedLen, and contains
	// a defanged URL.  Pad to well above minDecodedLen (8 bytes).
	input := []byte(strings.Repeat("x", 20) + " hxxp://malware[.]example/payload " + strings.Repeat("x", 20))

	res := &Result{}
	fromEncoded(input, res, time.Time{})

	found := false
	for _, s := range res.Streams {
		if strings.Contains(string(s), "http://malware.example/payload") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("fromEncoded did not emit a stream containing the un-defanged URL; streams=%d", len(res.Streams))
		for i, s := range res.Streams {
			t.Logf("  stream[%d] = %q", i, s)
		}
	}
}

// TestFromEncodedDefangThenBase64 verifies the "defang → looksEncoded →
// decodeSourceTree" path: if the un-defanged result itself carries a long
// base64 run, the downstream decode pass unwraps it.
func TestFromEncodedDefangThenBase64(t *testing.T) {
	t.Parallel()

	// Inner payload that should ultimately surface.
	inner := "powershell -Command IEX (New-Object Net.WebClient).DownloadString"
	b64 := base64.StdEncoding.EncodeToString([]byte(inner))

	// Wrap the base64 blob in a defanged URL context.  The defanged bracket
	// around the dot makes the whole thing a defanged IOC; after un-defanging
	// the resulting buffer contains the long base64 run → looksEncoded → true →
	// decodeSourceTree unwraps it.
	//
	// Format: "hxxp://evil[.]com/?data=<base64>"
	// After undefang: "http://evil.com/?data=<base64>"
	//
	// Use enough padding text that mostlyText() passes and the blob clears minDecodedLen.
	carrier := []byte("hxxp://evil[.]com/?data=" + b64 + " extra-padding-for-text-gate")

	res := &Result{}
	fromEncoded(carrier, res, time.Time{})

	// We expect at minimum two streams: the un-defanged URL string and the
	// base64-decoded inner payload.
	foundDefanged := false
	foundDecoded := false
	for _, s := range res.Streams {
		str := string(s)
		if strings.Contains(str, "http://evil.com") {
			foundDefanged = true
		}
		if strings.Contains(str, "powershell") {
			foundDecoded = true
		}
	}
	if !foundDefanged {
		t.Error("expected un-defanged stream not found")
	}
	if !foundDecoded {
		t.Errorf("expected base64-decoded stream containing 'powershell' not found; streams=%d", len(res.Streams))
		for i, s := range res.Streams {
			t.Logf("  stream[%d] = %q", i, s)
		}
	}
}

// TestUndefangLargeInputClamped verifies that a buffer larger than maxFoldInput
// is processed without panic and that the returned slice length does not exceed
// maxFoldInput.
func TestUndefangLargeInputClamped(t *testing.T) {
	t.Parallel()

	large := make([]byte, maxFoldInput+1024)
	// Plant a defang marker near the start.
	copy(large, []byte("hxxp://evil[.]com/"))
	// Fill the rest with printable text.
	for i := 18; i < len(large); i++ {
		large[i] = 'a'
	}

	out, ok := undefang(large)
	if !ok {
		t.Fatal("expected undefang to change the large buffer (has hxxp marker)")
	}
	if len(out) > maxFoldInput {
		t.Errorf("returned slice length %d exceeds maxFoldInput %d", len(out), maxFoldInput)
	}
}
