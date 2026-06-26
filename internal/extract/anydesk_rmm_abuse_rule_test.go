package extract

import (
	"bytes"
	"os"
	"testing"
)

// anydesk_rmm_abuse.yara lints — the unit suite does not link libyara; actual
// compile+match runs in the Docker `full` CI stage (compile-rules.sh). These
// guards pin the discriminating literals and the size gate so an edit cannot
// silently weaken the rule. blacktop/yara 4.2.3: fires on sample 12648cd9…,
// clean on a benign AnyDesk-launch batch.

func loadAnyDeskRule(t *testing.T) []byte {
	t.Helper()
	for _, p := range []string{
		"../../../../docker/local-rules/anydesk_rmm_abuse.yara",
		"../../../docker/local-rules/anydesk_rmm_abuse.yara",
		"../../docker/local-rules/anydesk_rmm_abuse.yara",
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("anydesk_rmm_abuse.yara not found relative to test dir")
	return nil
}

func TestAnyDeskRule(t *testing.T) {
	data := loadAnyDeskRule(t)
	for _, want := range []string{
		"rule AnyDesk_Unattended_Access_Abuse",
		`"AnyDesk" nocase`,
		`"--set-password" nocase`,
		`"_unattended_access" nocase`, // the discriminating flag — never benign in a mail .bat
		"filesize < 65536",
		"all of them",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("anydesk_rmm_abuse.yara missing %q", want)
		}
	}
}
