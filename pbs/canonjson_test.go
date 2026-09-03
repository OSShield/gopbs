package pbs_test

import (
	"strings"
	"testing"

	"github.com/osshield/gopbs/pbs"
)

func TestCanonicalJSONShape(t *testing.T) {
	m := pbs.BackupManifest{
		BackupID:   "id",
		BackupTime: 42,
		BackupType: "host",
		Files: []pbs.ManifestFile{
			{CryptMode: "none", Csum: "00", Filename: "z \"quoted\" \\back <&> äö\n\x01", Size: 1},
		},
	}
	canon, err := pbs.CanonicalManifestJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	got := string(canon)

	// Keys sorted bytewise, no whitespace: backup-id < backup-time <
	// backup-type < files; within a file: crypt-mode < csum < filename < size.
	wantOrder := []string{`"backup-id"`, `"backup-time"`, `"backup-type"`, `"files"`, `"crypt-mode"`, `"csum"`, `"filename"`, `"size"`}
	last := -1
	for _, k := range wantOrder {
		i := strings.Index(got, k)
		if i <= last {
			t.Fatalf("key %s out of order in %s", k, got)
		}
		last = i
	}

	// No structural whitespace: spaces only inside string values, and the
	// filename's literal newline arrives escaped.
	if strings.ContainsAny(got, "\t\n\r") || strings.Contains(got, `", "`) || strings.Contains(got, `": `) {
		t.Fatalf("canonical form contains structural whitespace: %q", got)
	}

	// serde_json escaping: quote and backslash escaped; HTML characters and
	// non-ASCII pass through unescaped (encoding/json alone would escape
	// them); control characters as short escapes or lowercase hex.
	wants := []string{"\\\"quoted\\\"", "\\\\back", "<&>", "äö", "\\n", "\\u0001"}
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Fatalf("canonical form %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "u003c") || strings.Contains(got, "u0026") {
		t.Fatalf("canonical form HTML-escapes: %q", got)
	}
}

func TestCanonicalJSONRejectsNull(t *testing.T) {
	// A nil Files slice marshals as a null member; the writer must refuse to
	// sign a document containing values it cannot canonicalize.
	m := pbs.BackupManifest{BackupID: "id", BackupTime: 1, BackupType: "host"}
	if _, err := pbs.CanonicalManifestJSON(m); err == nil || !strings.Contains(err.Error(), "null") {
		t.Fatalf("nil files: got %v, want null rejection", err)
	}

	m.Files = []pbs.ManifestFile{}
	if _, err := pbs.CanonicalManifestJSON(m); err != nil {
		t.Fatalf("empty files: %v", err)
	}
}
