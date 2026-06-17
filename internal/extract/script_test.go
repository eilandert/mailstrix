package extract

import (
	"bytes"
	"testing"
)

// TestDecodeScriptCanonical verifies the screnc decoder against the canonical
// example from Didier Stevens' decode-vbe.py:
//
//	Input:  #@~^DgAAAA==\ko$K6,JC\x7fV^GJqAQAAA==^#~@
//	Output: MsgBox "Hello"  (+ 8 trailing bytes from the checksum field)
//
// Source: https://github.com/DidierStevens/DidierStevensSuite/blob/master/decode-vbe.py
// The body fed to decodeScript is extracted exactly as fromEncodedScript does:
// skip the 4-byte "#@~^" marker and the 8-byte length field, then take
// everything up to "^#~@". The trailing "AAAAAA==" (the fake length/checksum
// field before the terminator) decodes to 8 garbage bytes that are included in
// the output — matching reference behaviour.
func TestDecodeScriptCanonical(t *testing.T) {
	// The encoded body (between "#@~^DgAAAA==" and "^#~@"):
	//   \  k  o  $  K  6  ,  J  C  \x7f  V  ^  G  J  q  A  Q  A  A  A  =  =
	encodedBody := []byte(
		"\x5c\x6b\x6f\x24\x4b\x36\x2c\x4a\x43\x7f\x56\x5e\x47\x4a\x71\x41\x51\x41\x41\x41\x3d\x3d",
	)

	// Expected output verified against decode-vbe.py run on the same input.
	// "MsgBox \"Hello\"" = first 14 bytes; last 8 are checksum-field garbage.
	want := []byte("MsgBox \"Hello\"WB+BEB~~")

	got := decodeScript(encodedBody)
	if !bytes.Equal(got, want) {
		t.Errorf("decodeScript(%q)\n  got  %q\n  want %q", encodedBody, got, want)
	}
}

// TestFromEncodedScriptCanonical exercises the full extraction path using the
// same canonical vector, wrapped in a complete screnc block.
func TestFromEncodedScriptCanonical(t *testing.T) {
	// Full screnc block: #@~^DgAAAA==<body>^#~@
	// Body: \ko$K6,JC\x7fV^GJqAQAAA==
	input := []byte(
		"#@~^DgAAAA==" +
			"\x5c\x6b\x6f\x24\x4b\x36\x2c\x4a\x43\x7f\x56\x5e\x47\x4a\x71\x41\x51\x41\x41\x41\x3d\x3d" +
			"^#~@",
	)

	want := []byte("MsgBox \"Hello\"WB+BEB~~")

	res := &Result{}
	fromEncodedScript(input, res)

	if !res.EncodedScript {
		t.Fatal("fromEncodedScript: EncodedScript flag not set")
	}
	if len(res.Streams) != 1 {
		t.Fatalf("fromEncodedScript: got %d streams, want 1", len(res.Streams))
	}
	if !bytes.Equal(res.Streams[0], want) {
		t.Errorf("fromEncodedScript stream[0]\n  got  %q\n  want %q", res.Streams[0], want)
	}
}

// TestDecodeScriptAtEscapes verifies that @-escape sequences are decoded
// correctly: @& → \n, @# → \r, @* → >, @! → <, @$ → @.
// These bytes are not run through the substitution table; the combination
// index does NOT advance for them.
func TestDecodeScriptAtEscapes(t *testing.T) {
	// A body consisting only of @-escapes produces the literal escape chars.
	// The combination index stays at 0 throughout (no substitutable bytes).
	encodedBody := []byte("@&@#@*@!@$")
	want := []byte{'\n', '\r', '>', '<', '@'}

	got := decodeScript(encodedBody)
	if !bytes.Equal(got, want) {
		t.Errorf("decodeScript(@-escapes): got %q, want %q", got, want)
	}
}

// TestDecodeScriptPassThrough checks that bytes outside the substitution range
// (0x00–0x08 control chars and high bytes >= 128) pass through unchanged.
func TestDecodeScriptPassThrough(t *testing.T) {
	// Bytes 0x01 and 0x80 should be emitted as-is.
	input := []byte{0x01, 0x80}
	got := decodeScript(input)
	if !bytes.Equal(got, input) {
		t.Errorf("decodeScript(passthrough): got %v, want %v", got, input)
	}
}

// TestFromEncodedScriptEmpty verifies that a buffer with no screnc marker
// produces no streams and does not panic.
func TestFromEncodedScriptEmpty(t *testing.T) {
	res := &Result{}
	fromEncodedScript([]byte("nothing to see here"), res)
	if res.EncodedScript || len(res.Streams) != 0 {
		t.Errorf("unexpected result on plain input: %+v", res)
	}
}
