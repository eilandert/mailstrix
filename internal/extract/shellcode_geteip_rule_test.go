package extract

import (
	"bytes"
	"os"
	"testing"
)

// shellcode_geteip.yara lints — the unit suite does not link libyara; actual
// compile+match runs in the Docker `full` CI stage (compile-rules.sh). These
// guards pin the byte patterns and the non-PE FP-gate so an edit cannot silently
// weaken the rule (a dropped gate would FP on every benign PE; a mangled hex
// literal would stop matching real shellcode).

func loadShellcodeGetEIPRule(t *testing.T) []byte {
	t.Helper()
	for _, p := range []string{
		"../../../../docker/local-rules/shellcode_geteip.yara",
		"../../../docker/local-rules/shellcode_geteip.yara",
		"../../docker/local-rules/shellcode_geteip.yara",
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("shellcode_geteip.yara not found relative to test dir")
	return nil
}

func TestShellcodeGetEIPRule_Present(t *testing.T) {
	data := loadShellcodeGetEIPRule(t)
	for _, want := range []string{
		"rule Shellcode_GetEIP",
		// call/pop GetEIP: E8 00 00 00 00 then a pop reg.
		"E8 00 00 00 00 (58|59|5A|5B|5E|5F)",
		// Didier-Stevens fnstenv GetEIP then a pop reg.
		"D9 EE D9 74 24 F4 (58|59|5A|5B|5E|5F)",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("shellcode_geteip.yara missing %q", want)
		}
	}
}

// The non-PE gate is the FP firewall: without it the stubs fire on benign PEs.
func TestShellcodeGetEIPRule_NonPEGate(t *testing.T) {
	data := loadShellcodeGetEIPRule(t)
	if !bytes.Contains(data, []byte("not uint16(0) == 0x5A4D")) {
		t.Error("shellcode_geteip.yara missing the `not uint16(0) == 0x5A4D` non-PE gate — would FP on benign PE images")
	}
	if !bytes.Contains(data, []byte("filesize >= 64")) {
		t.Error("shellcode_geteip.yara missing the filesize >= 64 minimum-size gate")
	}
}

func TestShellcodeGetEIPRule_NoBackreference(t *testing.T) {
	data := loadShellcodeGetEIPRule(t)
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`)} {
		if bytes.Contains(data, bad) {
			t.Errorf("shellcode_geteip.yara contains backreference %q — yarac rejects it", bad)
		}
	}
}
