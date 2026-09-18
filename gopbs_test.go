package gopbs_test

import (
	"context"
	"strings"
	"testing"

	"github.com/osshield/gopbs"
)

// Backup's option validation runs before any connection is made, so the
// error cases are testable without a server.
func TestBackupOptionValidation(t *testing.T) {
	base := gopbs.BackupOptions{Paths: []string{"/"}}

	for _, tc := range []struct {
		name    string
		mutate  func(*gopbs.BackupOptions)
		wantErr string
	}{
		{
			"unknown format",
			func(o *gopbs.BackupOptions) { o.Format = gopbs.Format(99) },
			"unknown format",
		},
		{
			"nothing to back up",
			func(o *gopbs.BackupOptions) { o.Paths = nil },
			"nothing to back up",
		},
		{
			"invalid exclude pattern",
			func(o *gopbs.BackupOptions) { o.Archive.Scan.Exclude = []string{"[abc"} },
			"invalid exclude pattern",
		},
		{
			"empty blob name",
			func(o *gopbs.BackupOptions) { o.Blobs = []gopbs.Blob{{Name: ""}} },
			"empty name",
		},
		{
			"blob name with slash",
			func(o *gopbs.BackupOptions) { o.Blobs = []gopbs.Blob{{Name: "a/b"}} },
			"invalid blob name",
		},
		{
			"reserved manifest name",
			func(o *gopbs.BackupOptions) { o.Blobs = []gopbs.Blob{{Name: "index.json"}} },
			"reserved",
		},
		{
			"duplicate after suffix normalization",
			func(o *gopbs.BackupOptions) {
				o.Blobs = []gopbs.Blob{{Name: "meta"}, {Name: "meta.blob"}}
			},
			"duplicate blob name",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			tc.mutate(&opts)
			_, err := gopbs.Backup(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
