package extract

import (
	"bytes"
	"os"
	"testing"
)

// ps1_dotnet_lolbin_killer.yara lints — the unit suite does not link libyara;
// actual compile+match runs in the Docker `full` CI stage (compile-rules.sh).
// These guards pin the .NET-Framework-path + managed-LOLBin conjunction and the
// size gate so an edit cannot silently weaken the rule. blacktop/yara 4.2.3:
// fires on sample 0c627ab6…, clean on a benign Stop-Process script.

func loadPS1LOLBinRule(t *testing.T) []byte {
	t.Helper()
	for _, p := range []string{
		"../../../../docker/local-rules/ps1_dotnet_lolbin_killer.yara",
		"../../../docker/local-rules/ps1_dotnet_lolbin_killer.yara",
		"../../docker/local-rules/ps1_dotnet_lolbin_killer.yara",
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("ps1_dotnet_lolbin_killer.yara not found relative to test dir")
	return nil
}

func TestPS1LOLBinRule(t *testing.T) {
	data := loadPS1LOLBinRule(t)
	for _, want := range []string{
		"rule PS1_DotNet_LOLBin_Killer_Loader",
		`"Microsoft.NET\\Framework" nocase`,
		`"aspnet_compiler" nocase`,
		`"AddInProcess" nocase`,
		"filesize < 262144",
		"all of them",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("ps1_dotnet_lolbin_killer.yara missing %q", want)
		}
	}
}

func TestPS1LOLBinRule_NoBackreference(t *testing.T) {
	data := loadPS1LOLBinRule(t)
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`)} {
		if bytes.Contains(data, bad) {
			t.Errorf("ps1_dotnet_lolbin_killer.yara contains backreference %q — yarac rejects it", bad)
		}
	}
}
