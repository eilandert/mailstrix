package extract

import (
	"testing"
)

// FuzzParseBIFF8Formula verifies the three invariants of parseBIFF8Formula for
// arbitrary byte inputs:
//  1. Never panics (a panic propagates through f.Fuzz and fails the run).
//  2. Always terminates (the token + stack + output caps guarantee this).
//  3. The returned string never exceeds maxBIFFPtgOutputLen bytes.
//
// No content assertions are made — the input is untrusted and the output is
// deliberately unspecified beyond the length bound.
func FuzzParseBIFF8Formula(f *testing.F) {
	// Seed: empty input.
	f.Add([]byte(nil))
	f.Add([]byte{})

	// Seed: single ptgStr8 "evil.com".
	f.Add(ptgStr8("evil.com"))

	// Seed: two ptgStr8 tokens concatenated with ptgConcat — "http" & "://x".
	{
		s := append(ptgStr8("http"), ptgStr8("://x")...)
		s = append(s, ptgConcat)
		f.Add(s)
	}

	// Seed: ptgInt literal.
	f.Add(ptgIntTok(0x1234))

	// Seed: ptgStr8 "calc.exe" + ptgFunc for EXEC (id 110) → =EXEC(calc.exe).
	f.Add(append(ptgStr8("calc.exe"), ptgFuncTok(110)...))

	// Seed: two-arg ptgFuncVar for CALL (id 150).
	{
		s := append(ptgStr8("kernel32"), ptgStr8("VirtualAlloc")...)
		s = append(s, ptgFuncVarTok(2, 150)...)
		f.Add(s)
	}

	// Seed: truncated ptgStr — cch says 10, only 2 chars follow.
	{
		s := ptgStr8("pre")
		s = append(s, ptgStr, 10, 0x00, 'h', 'i') // truncated body
		f.Add(s)
	}

	// Seed: unknown ptg opcode 0x7A — parser must bail without desyncing.
	f.Add(append(ptgStr8("kept"), 0x7A, 0xFF, 0xFF))

	// Seed: ptgFuncVar with USERDEFINED (0x806D) trailer — argc=0 + 9 trailer bytes.
	{
		s := ptgFuncVarTok(0, funcUserDefined)
		s = append(s, make([]byte, 9)...) // 9-byte USERDEFINED trailer
		s = append(s, ptgStr8("after")...)
		f.Add(s)
	}

	// Seed: pure random garbage.
	f.Add([]byte{0xFF, 0xFE, 0x00, 0xAB, 0xCD, 0xEF, 0x42, 0x00, 0x17, 0x03, 0x00, 'a', 'b', 'c'})

	f.Fuzz(func(t *testing.T, data []byte) {
		result := parseBIFF8Formula(data)
		if len(result) > maxBIFFPtgOutputLen {
			t.Fatalf("output length %d exceeds maxBIFFPtgOutputLen %d", len(result), maxBIFFPtgOutputLen)
		}
	})
}
