//go:build integration

package main_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	gopbs "github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/scan"
)

// End-to-end tests against a real Proxmox Backup Server (the epbs service in
// compose.yml, github.com/osshield/ephemeral-pbs). Every snapshot gopbs
// writes is checked three ways: the REST API (listing, notes, owner, files,
// a server-side verify task, single-file download), the official
// proxmox-backup-client in a container (restore, catalog dump, notes,
// protection), and gopbs's own reader side.
const (
	epbsURL          = "https://localhost:8017"
	epbsStore        = "data"
	epbsSecret       = "12345678-1234-1234-1234-1234567890ab"
	epbsBackupToken  = "backupuser@pbs!backup"
	epbsRestoreToken = "restoreuser@pbs!restore"
	epbsRootUser     = "root@pam"
	epbsRootPassword = "demo"
)

var epbsFingerprint string // discovered by startEPBS

// startEPBS brings up the real PBS, waits until its users and tokens exist,
// and records its certificate fingerprint. GOPBS_KEEP_PBS=1 keeps it running
// (web UI at epbsURL, root@pam / demo).
func startEPBS(t *testing.T) {
	t.Helper()
	if err := compose("up", "-d", "epbs"); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("GOPBS_KEEP_PBS") == "" {
		t.Cleanup(func() {
			if err := compose("rm", "-sf", "epbs"); err != nil {
				t.Logf("epbs teardown: %v", err)
			}
		})
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		err := func() error {
			fp, err := tlsFingerprint(strings.TrimPrefix(epbsURL, "https://"))
			if err != nil {
				return err
			}
			epbsFingerprint = fp
			// The setup script creates the tokens last; the token listing
			// its own (empty) datastore proves everything is in place.
			_, err = epbsToken(epbsBackupToken).get(t, "/admin/datastore/"+epbsStore+"/groups", nil)
			return err
		}()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ephemeral-pbs not ready in time: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
}

func tlsFingerprint(addr string) (string, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	sum := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":"), nil
}

// epbsAPI is a minimal REST client for the checks gopbs has no API for.
type epbsAPI struct {
	header http.Header
	http   *http.Client
}

func newEPBSAPI() *epbsAPI {
	return &epbsAPI{header: http.Header{}, http: &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			sum := sha256.Sum256(raw[0])
			if got := hex.EncodeToString(sum[:]); got != strings.ToLower(strings.ReplaceAll(epbsFingerprint, ":", "")) {
				return fmt.Errorf("fingerprint changed: %s", got)
			}
			return nil
		}},
	}}}
}

func epbsToken(id string) *epbsAPI {
	a := newEPBSAPI()
	a.header.Set("Authorization", "PBSAPIToken="+id+":"+epbsSecret)
	return a
}

// epbsRoot logs in as root@pam with a ticket; needed for verify tasks.
func epbsRoot(t *testing.T) *epbsAPI {
	t.Helper()
	a := newEPBSAPI()
	form := url.Values{"username": {epbsRootUser}, "password": {epbsRootPassword}}
	resp, err := a.http.PostForm(epbsURL+"/api2/json/access/ticket", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var parsed struct {
		Data struct {
			Ticket string `json:"ticket"`
			CSRF   string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil || parsed.Data.Ticket == "" {
		t.Fatalf("root login: %v (status %s)", err, resp.Status)
	}
	a.header.Set("Cookie", "PBSAuthCookie="+parsed.Data.Ticket)
	a.header.Set("CSRFPreventionToken", parsed.Data.CSRF)
	return a
}

func (a *epbsAPI) do(method, path string, query url.Values, body any) (json.RawMessage, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, epbsURL+"/api2/json"+path+"?"+query.Encode(), rd)
	if err != nil {
		return nil, err
	}
	req.Header = a.header.Clone()
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, raw)
	}
	var parsed struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return raw, nil // non-JSON bodies (file downloads) are returned as-is
	}
	return parsed.Data, nil
}

func (a *epbsAPI) get(t *testing.T, path string, query url.Values) (json.RawMessage, error) {
	t.Helper()
	return a.do(http.MethodGet, path, query, nil)
}

func (a *epbsAPI) mustGet(t *testing.T, path string, query url.Values, into any) {
	t.Helper()
	data, err := a.get(t, path, query)
	if err != nil {
		t.Fatal(err)
	}
	if into != nil {
		if err := json.Unmarshal(data, into); err != nil {
			t.Fatalf("%s: %v: %s", path, err, data)
		}
	}
}

// snapshotQuery addresses one snapshot the way the datastore endpoints do.
func snapshotQuery(ref pbs.SnapshotRef, ns string) url.Values {
	q := url.Values{
		"backup-type": {ref.Type},
		"backup-id":   {ref.ID},
		"backup-time": {fmt.Sprint(ref.Time.Unix())},
	}
	if ns != "" {
		q.Set("ns", ns)
	}
	return q
}

func snapshotPath(ref pbs.SnapshotRef) string {
	return fmt.Sprintf("%s/%s/%s", ref.Type, ref.ID, ref.Time.UTC().Format(time.RFC3339))
}

// snapshotEntry is the subset of the snapshot listing the tests check.
type snapshotEntry struct {
	BackupID   string `json:"backup-id"`
	BackupTime int64  `json:"backup-time"`
	Comment    string `json:"comment"`
	Owner      string `json:"owner"`
	Size       uint64 `json:"size"`
	Protected  bool   `json:"protected"`
	Files      []struct {
		Filename  string `json:"filename"`
		CryptMode string `json:"crypt-mode"`
		Size      uint64 `json:"size"`
	} `json:"files"`
	Verification *struct {
		State string `json:"state"`
	} `json:"verification"`
}

func listSnapshot(t *testing.T, api *epbsAPI, ref pbs.SnapshotRef, ns string) snapshotEntry {
	t.Helper()
	q := snapshotQuery(ref, ns)
	q.Del("backup-time")
	var entries []snapshotEntry
	api.mustGet(t, "/admin/datastore/"+epbsStore+"/snapshots", q, &entries)
	for _, e := range entries {
		if e.BackupTime == ref.Time.Unix() {
			return e
		}
	}
	t.Fatalf("snapshot %s not listed (got %+v)", snapshotPath(ref), entries)
	return snapshotEntry{}
}

// verifySnapshot runs the server-side verify task (chunk digests, index
// checksums, blob CRCs recomputed by PBS itself) and requires it to pass.
func verifySnapshot(t *testing.T, ref pbs.SnapshotRef, ns string) {
	t.Helper()
	root := epbsRoot(t)
	body := map[string]any{"backup-type": ref.Type, "backup-id": ref.ID, "backup-time": ref.Time.Unix()}
	if ns != "" {
		body["ns"] = ns
	}
	data, err := root.do(http.MethodPost, "/admin/datastore/"+epbsStore+"/verify", nil, body)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var upid string
	if err := json.Unmarshal(data, &upid); err != nil {
		t.Fatalf("verify: %v: %s", err, data)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		var status struct {
			Status     string `json:"status"`
			ExitStatus string `json:"exitstatus"`
		}
		root.mustGet(t, "/nodes/localhost/tasks/"+url.PathEscape(upid)+"/status", nil, &status)
		if status.Status == "stopped" {
			if status.ExitStatus != "OK" {
				log, _ := root.get(t, "/nodes/localhost/tasks/"+url.PathEscape(upid)+"/log", nil)
				t.Fatalf("verify task %s: %s\n%s", upid, status.ExitStatus, log)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("verify task %s still %s", upid, status.Status)
		}
		time.Sleep(time.Second)
	}
}

// pxarFileDownload fetches one file out of an archive through the datastore
// API (the server seeks into the archive using the index gopbs uploaded).
func pxarFileDownload(t *testing.T, api *epbsAPI, ref pbs.SnapshotRef, ns, archiveIndex, path string) []byte {
	t.Helper()
	q := snapshotQuery(ref, ns)
	q.Set("filepath", base64.StdEncoding.EncodeToString([]byte("/"+archiveIndex+"/"+path)))
	data, err := api.get(t, "/admin/datastore/"+epbsStore+"/pxar-file-download", q)
	if err != nil {
		t.Fatalf("pxar-file-download %s: %v", path, err)
	}
	return data
}

// cli runs one proxmox-backup-client subcommand in a container against the
// real PBS and returns its stdout. The token's secret goes in PBS_PASSWORD,
// as the official client expects.
func cli(t *testing.T, token, ns string, args ...string) string {
	t.Helper()
	out, err := composeOutput("run", "--rm", "--remove-orphans", "-T",
		"-e", "REPO="+token+"@pbs:"+epbsStore,
		"-e", "PBS_PASSWORD="+epbsSecret,
		"-e", "PBS_FINGERPRINT="+epbsFingerprint,
		"-e", "NS="+ns,
		"-e", "ARGS="+strings.Join(args, " "),
		"pbscli")
	if err != nil {
		t.Fatalf("proxmox-backup-client %s: %v", strings.Join(args, " "), err)
	}
	return out
}

// officialRestore restores an archive (or, raw, a blob) of a snapshot with
// the official client into .test-restore/<target> and returns the host path.
func officialRestore(t *testing.T, ref pbs.SnapshotRef, ns, archive, target, keyfile string, raw bool) string {
	t.Helper()
	args := []string{"run", "--rm", "--remove-orphans",
		"-e", "REPO=" + epbsBackupToken + "@pbs:" + epbsStore,
		"-e", "PBS_PASSWORD=" + epbsSecret,
		"-e", "PBS_FINGERPRINT=" + epbsFingerprint,
		"-e", "NS=" + ns,
		"-e", "SNAPSHOT=" + snapshotPath(ref),
		"-e", "ARCHIVE=" + archive,
		"-e", "TARGET=/restore/" + target,
		"-e", "KEYFILE=" + keyfile,
	}
	if raw {
		args = append(args, "-e", "RAW=1")
	}
	if err := compose(append(args, "pbsrestore")...); err != nil {
		t.Fatalf("official restore of %s: %v", archive, err)
	}
	return filepath.Join(restoreDir, target)
}

// catalogDump returns the paths of `proxmox-backup-client catalog dump`,
// relative to the archive root, with their entry type.
func catalogDump(t *testing.T, ref pbs.SnapshotRef, ns, archive string) map[string]string {
	t.Helper()
	out := cli(t, epbsBackupToken, ns, "catalog", "dump", snapshotPath(ref)) // dumps every catalog of the snapshot
	re := regexp.MustCompile(`^(\S+) "\./` + regexp.QuoteMeta(archive+".didx") + `/?([^"]*)"`)
	paths := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if m := re.FindStringSubmatch(line); m != nil && m[2] != "" {
			paths[m[2]] = m[1]
		}
	}
	if len(paths) == 0 {
		t.Fatalf("catalog dump: no entries parsed from:\n%s", out)
	}
	return paths
}

// treePaths lists a directory tree's relative paths; directories map to "d".
func treePaths(t *testing.T, root string) map[string]string {
	t.Helper()
	paths := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if rel, _ := filepath.Rel(root, p); rel != "." {
			paths[rel] = map[bool]string{true: "d", false: "f"}[d.IsDir()]
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func epbsConfig(auth pbs.Auth) pbs.Config {
	return pbs.Config{
		BaseURL:      epbsURL,
		Auth:         auth,
		Fingerprint:  epbsFingerprint,
		Datastore:    epbsStore,
		Workers:      4,
		ChunkSizeAvg: 128 << 10,
	}
}

func tokenAuth(id string) pbs.Auth { return pbs.TokenAuth{AuthID: id, Secret: epbsSecret} }

// checkListing asserts the REST listing of a fresh snapshot: owner, comment,
// the exact set of files with their crypt mode, and size.
func checkListing(t *testing.T, ref pbs.SnapshotRef, ns, owner, notes, cryptMode string, files ...string) snapshotEntry {
	t.Helper()
	e := listSnapshot(t, epbsToken(epbsBackupToken), ref, ns)
	if e.Owner != owner {
		t.Errorf("owner %q, want %q", e.Owner, owner)
	}
	if e.Comment != notes {
		t.Errorf("comment %q, want %q", e.Comment, notes)
	}
	if e.Size == 0 {
		t.Error("listed size is 0")
	}
	var got []string
	for _, f := range e.Files {
		got = append(got, f.Filename)
		if f.CryptMode != cryptMode && f.Filename != "index.json.blob" && f.Filename != "rsa-encrypted.key.blob" {
			t.Errorf("%s: crypt-mode %q, want %q", f.Filename, f.CryptMode, cryptMode)
		}
	}
	sort.Strings(got)
	sort.Strings(files)
	if !slices.Equal(got, files) {
		t.Errorf("files %v, want %v", got, files)
	}
	return e
}

func mustBackup(t *testing.T, opts gopbs.BackupOptions) *gopbs.BackupResult {
	t.Helper()
	res, err := gopbs.Backup(context.Background(), opts)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	for _, w := range res.Warnings {
		if !strings.Contains(w.Err.Error(), ".pxarexclude-cli is reserved") { // the exclude fixture plants one on purpose
			t.Errorf("backup warning: %v", w)
		}
	}
	return res
}

func TestEphemeralPBS(t *testing.T) {
	startEPBS(t)
	ctx := context.Background()
	src := filepath.Join(sourceDir, "epbs")
	writeRestoreTree(t, src) // 20 files, symlink, hardlink, random mtimes
	// A file to spot-check through pxar-file-download and the catalog.
	probe := "d1/s1/f1.bin"
	probeData, err := os.ReadFile(filepath.Join(src, probe))
	if err != nil {
		t.Fatal(err)
	}
	// The blob and its exact content, uploaded alongside most snapshots.
	meta := gopbs.Blob{Name: "app-meta.json", Data: []byte(`{"app":"gopbs-e2e","kept-for":"90d"}`)}
	run := time.Now().UnixNano()

	// v1 with catalog, notes and a blob, token auth: the full verification
	// matrix, then a second run that must deduplicate completely.
	t.Run("v1", func(t *testing.T) {
		notes := "nightly /etc from web-01 — gopbs e2e"
		opts := gopbs.BackupOptions{
			Client:  epbsConfig(tokenAuth(epbsBackupToken)),
			Archive: archive.Options{Name: "root"},
			Ref:     pbs.SnapshotRef{Type: "host", ID: fmt.Sprintf("e2e-v1-%d", run), Notes: notes},
			Paths:   []string{src},
			Blobs:   []gopbs.Blob{meta},
		}
		res := mustBackup(t, opts)
		ref := res.Ref

		// REST: listing, server-side verify, single-file download, notes.
		checkListing(t, ref, "", epbsBackupToken, notes, "none",
			"root.pxar.didx", "catalog.pcat1.didx", "index.json.blob", "app-meta.json.blob")
		verifySnapshot(t, ref, "")
		if e := listSnapshot(t, epbsToken(epbsBackupToken), ref, ""); e.Verification == nil || e.Verification.State != "ok" {
			t.Errorf("verification state after verify: %+v", e.Verification)
		}
		if got := pxarFileDownload(t, epbsToken(epbsBackupToken), ref, "", "root.pxar.didx", probe); !bytes.Equal(got, probeData) {
			t.Errorf("pxar-file-download %s: %d bytes, want %d", probe, len(got), len(probeData))
		}
		var gotNotes string
		epbsToken(epbsBackupToken).mustGet(t, "/admin/datastore/"+epbsStore+"/notes", snapshotQuery(ref, ""), &gotNotes)
		if gotNotes != notes {
			t.Errorf("notes endpoint %q, want %q", gotNotes, notes)
		}

		// Official client: restore, blob, catalog dump, notes, protection.
		dst := officialRestore(t, ref, "", "root.pxar", "epbs-v1", "", false)
		if eq, err := compareTrees(dst, src); err != nil || !eq {
			t.Errorf("official restore differs from source (err %v)", err)
		}
		blob := officialRestore(t, ref, "", "app-meta.json.blob", "epbs-v1-meta.json", "", true)
		if got, _ := os.ReadFile(blob); !bytes.Equal(got, meta.Data) {
			t.Errorf("restored blob %q, want %q", got, meta.Data)
		}
		want := treePaths(t, src)
		got := catalogDump(t, ref, "", "root.pxar")
		if !slices.Equal(sortedKeys(got), sortedKeys(want)) {
			t.Errorf("catalog dump paths %v\nwant %v", sortedKeys(got), sortedKeys(want))
		}
		for p, typ := range want {
			if typ == "d" && got[p] != "d" {
				t.Errorf("catalog dump: %s is %q, want a directory", p, got[p])
			}
		}
		if out := cli(t, epbsBackupToken, "", "snapshot", "notes", "show", snapshotPath(ref)); strings.TrimSpace(out) != notes {
			t.Errorf("notes show %q, want %q", strings.TrimSpace(out), notes)
		}
		cli(t, epbsBackupToken, "", "snapshot", "protected", "update", snapshotPath(ref), "true")

		// gopbs reader side with the read-only token.
		reader, err := pbs.NewClient(epbsConfig(tokenAuth(epbsRestoreToken)))
		if err != nil {
			t.Fatal(err)
		}
		snaps, err := reader.ListSnapshots(ctx, ref.Type, ref.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(snaps) != 1 || !snaps[0].Protected || snaps[0].Ref.Time.Unix() != ref.Time.Unix() {
			t.Errorf("ListSnapshots = %+v, want one protected snapshot at %v", snaps, ref.Time)
		}
		rdst := t.TempDir()
		rres, err := gopbs.Restore(ctx, gopbs.RestoreOptions{Client: epbsConfig(tokenAuth(epbsRestoreToken)), Ref: ref, Archive: "root", Target: rdst})
		if err != nil {
			t.Fatal(err)
		}
		if rres.Format != gopbs.FormatV1 || len(rres.Warnings) != 0 {
			t.Errorf("gopbs restore: format %v, warnings %v", rres.Format, rres.Warnings)
		}
		sameTree(t, src, rdst)
		sess, err := gopbs.OpenSnapshot(ctx, epbsConfig(tokenAuth(epbsRestoreToken)), ref, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()
		root, err := gopbs.Browse(ctx, sess, "root")
		if err != nil {
			t.Fatal(err)
		}
		if names := childNames(root); !slices.Equal(names, []string{"d0", "d1", "d2", "d3", "hard", "link"}) {
			t.Errorf("Browse root children %v", names)
		}

		// Dedup: same group, nothing new on the wire. Real PBS requires a
		// strictly newer backup time.
		time.Sleep(1100 * time.Millisecond)
		opts.Ref.Time = time.Time{}
		res2 := mustBackup(t, opts)
		if res2.Archive.NewChunks != 0 || res2.Archive.ReusedChunks != res2.Archive.ChunkCount {
			t.Errorf("second backup should deduplicate fully: %+v", res2.Archive)
		}
		verifySnapshot(t, res2.Ref, "")
	})

	// Password (ticket) auth, PAM realm, as root: the group is owned by
	// root@pam, so the backup token (Datastore.Backup on its own groups
	// only) must be refused while the reader token (Datastore.Read) is not.
	// (The static users' passwords are random per image build; the root
	// password is fixed.)
	t.Run("password", func(t *testing.T) {
		opts := gopbs.BackupOptions{
			Client:  epbsConfig(pbs.PasswordAuth{Username: "root", Realm: "pam", Password: epbsRootPassword}),
			Archive: archive.Options{Name: "home"},
			Ref:     pbs.SnapshotRef{Type: "host", ID: fmt.Sprintf("e2e-pw-%d", run)},
			Paths:   []string{src},
		}
		res := mustBackup(t, opts)
		// The token has Datastore.Backup only: the listing filters root's
		// group out instead of showing it.
		var hidden []snapshotEntry
		epbsToken(epbsBackupToken).mustGet(t, "/admin/datastore/"+epbsStore+"/snapshots", url.Values{"backup-type": {"host"}, "backup-id": {res.Ref.ID}}, &hidden)
		if len(hidden) != 0 {
			t.Errorf("backup token sees root's group: %+v", hidden)
		}
		e := listSnapshot(t, epbsRoot(t), res.Ref, "")
		if e.Owner != epbsRootUser {
			t.Errorf("owner %q, want %s", e.Owner, epbsRootUser)
		}
		verifySnapshot(t, res.Ref, "")
		if _, err := gopbs.Restore(ctx, gopbs.RestoreOptions{Client: epbsConfig(tokenAuth(epbsBackupToken)), Ref: res.Ref, Archive: "home", Target: t.TempDir()}); err == nil {
			t.Error("backup token restored root's group; expected an error")
		}
		dst := t.TempDir()
		if _, err := gopbs.Restore(ctx, gopbs.RestoreOptions{Client: epbsConfig(tokenAuth(epbsRestoreToken)), Ref: res.Ref, Archive: "home", Target: dst}); err != nil {
			t.Fatal(err)
		}
		sameTree(t, src, dst)
	})

	// v2 split archive: both streams listed, server verify, single-file
	// download out of the metadata archive, official and gopbs restores.
	t.Run("v2", func(t *testing.T) {
		opts := gopbs.BackupOptions{
			Client:  epbsConfig(tokenAuth(epbsBackupToken)),
			Archive: archive.Options{Name: "root"},
			Ref:     pbs.SnapshotRef{Type: "host", ID: fmt.Sprintf("e2e-v2-%d", run), Notes: "split archive"},
			Format:  gopbs.FormatV2,
			Paths:   []string{src},
		}
		res := mustBackup(t, opts)
		ref := res.Ref
		checkListing(t, ref, "", epbsBackupToken, "split archive", "none", "root.mpxar.didx", "root.ppxar.didx", "index.json.blob")
		verifySnapshot(t, ref, "")
		if got := pxarFileDownload(t, epbsToken(epbsBackupToken), ref, "", "root.mpxar.didx", probe); !bytes.Equal(got, probeData) {
			t.Errorf("pxar-file-download %s from mpxar: %d bytes, want %d", probe, len(got), len(probeData))
		}
		dst := officialRestore(t, ref, "", "root.pxar", "epbs-v2", "", false)
		if eq, err := compareTrees(dst, src); err != nil || !eq {
			t.Errorf("official restore differs from source (err %v)", err)
		}
		rdst := t.TempDir()
		rres, err := gopbs.Restore(ctx, gopbs.RestoreOptions{Client: epbsConfig(tokenAuth(epbsRestoreToken)), Ref: ref, Archive: "root", Target: rdst})
		if err != nil {
			t.Fatal(err)
		}
		if rres.Format != gopbs.FormatV2 {
			t.Errorf("format %v, want v2", rres.Format)
		}
		sameTree(t, src, rdst)

		time.Sleep(1100 * time.Millisecond)
		opts.Ref.Time = time.Time{}
		res2 := mustBackup(t, opts)
		if res2.Payload.NewChunks != 0 || res2.Archive.NewChunks != 0 {
			t.Errorf("second v2 backup uploaded chunks: meta %+v payload %+v", res2.Archive, res2.Payload)
		}
	})

	// Namespace, custom archive name, several paths plus a stream under the
	// virtual root, container type with a numeric id.
	t.Run("namespace", func(t *testing.T) {
		const ns = "level1/level2"
		streamData := bytes.Repeat([]byte("pg_dump output line\n"), 50_000)
		cfg := epbsConfig(tokenAuth(epbsBackupToken))
		cfg.Namespace = ns
		opts := gopbs.BackupOptions{
			Client:  cfg,
			Archive: archive.Options{Name: "etc-and-srv"},
			Ref:     pbs.SnapshotRef{Type: "ct", ID: "100", Notes: "ct 100 in level1/level2"},
			Paths:   []string{filepath.Join(src, "d0"), filepath.Join(src, "d1")},
			Streams: []gopbs.Stream{{Name: "dump.sql", Size: int64(len(streamData)), Reader: bytes.NewReader(streamData)}},
			Blobs:   []gopbs.Blob{meta},
		}
		res := mustBackup(t, opts)
		ref := res.Ref
		checkListing(t, ref, ns, epbsBackupToken, "ct 100 in level1/level2", "none",
			"etc-and-srv.pxar.didx", "catalog.pcat1.didx", "index.json.blob", "app-meta.json.blob")
		// Not visible outside its namespace.
		var rootNS []snapshotEntry
		epbsToken(epbsBackupToken).mustGet(t, "/admin/datastore/"+epbsStore+"/snapshots", url.Values{"backup-type": {"ct"}, "backup-id": {"100"}}, &rootNS)
		if len(rootNS) != 0 {
			t.Errorf("ct/100 visible in the root namespace: %+v", rootNS)
		}
		verifySnapshot(t, ref, ns)
		if got := pxarFileDownload(t, epbsToken(epbsBackupToken), ref, ns, "etc-and-srv.pxar.didx", "dump.sql"); !bytes.Equal(got, streamData) {
			t.Errorf("pxar-file-download dump.sql: %d bytes, want %d", len(got), len(streamData))
		}
		dst := officialRestore(t, ref, ns, "etc-and-srv.pxar", "epbs-ns", "", false)
		for _, d := range []string{"d0", "d1"} {
			if eq, err := compareTrees(filepath.Join(dst, d), filepath.Join(src, d)); err != nil || !eq {
				t.Errorf("official restore: %s differs from source (err %v)", d, err)
			}
		}
		if got, _ := os.ReadFile(filepath.Join(dst, "dump.sql")); !bytes.Equal(got, streamData) {
			t.Errorf("official restore: dump.sql %d bytes, want %d", len(got), len(streamData))
		}
		rcfg := epbsConfig(tokenAuth(epbsRestoreToken))
		rcfg.Namespace = ns
		rdst := t.TempDir()
		if _, err := gopbs.Restore(ctx, gopbs.RestoreOptions{Client: rcfg, Ref: ref, Archive: "etc-and-srv", Target: rdst}); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(filepath.Join(rdst, "dump.sql")); !bytes.Equal(got, streamData) {
			t.Errorf("gopbs restore: dump.sql %d bytes, want %d", len(got), len(streamData))
		}
		if eq, err := compareTrees(filepath.Join(rdst, "d1"), filepath.Join(src, "d1")); err != nil || !eq {
			t.Errorf("gopbs restore: d1 differs from source (err %v)", err)
		}
	})

	// Client-side encryption with a gopbs-made key file and a master key:
	// the official client decrypts with the key file, gopbs recovers the key
	// from the master-key wrapped copy, and the server verifies the
	// encrypted chunks.
	t.Run("encrypted", func(t *testing.T) {
		key, err := pbs.GenerateEncryptionKey()
		if err != nil {
			t.Fatal(err)
		}
		keyJSON, err := pbs.CreateKeyFile(key, nil, pbs.KDFNone, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keysDir, "epbs-key.json"), keyJSON, 0o600); err != nil {
			t.Fatal(err)
		}
		pub, err := os.ReadFile("../pbs/testdata/master-public.pem")
		if err != nil {
			t.Fatal(err)
		}
		priv, err := os.ReadFile("../pbs/testdata/master-private.pem")
		if err != nil {
			t.Fatal(err)
		}
		master, err := pbs.LoadMasterKey(priv, []byte("masterpass"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := epbsConfig(tokenAuth(epbsBackupToken))
		cfg.Crypt = &pbs.CryptConfig{Mode: pbs.CryptModeEncrypt, Key: key, MasterPublicKey: pub}
		opts := gopbs.BackupOptions{
			Client:  cfg,
			Archive: archive.Options{Name: "root"},
			Ref:     pbs.SnapshotRef{Type: "host", ID: fmt.Sprintf("e2e-enc-%d", run), Notes: "encrypted"},
			Paths:   []string{src},
			Blobs:   []gopbs.Blob{meta},
		}
		res := mustBackup(t, opts)
		ref := res.Ref
		checkListing(t, ref, "", epbsBackupToken, "encrypted", "encrypt",
			"root.pxar.didx", "catalog.pcat1.didx", "index.json.blob", "app-meta.json.blob", "rsa-encrypted.key.blob")
		verifySnapshot(t, ref, "")
		dst := officialRestore(t, ref, "", "root.pxar", "epbs-enc", "/keys/epbs-key.json", false)
		if eq, err := compareTrees(dst, src); err != nil || !eq {
			t.Errorf("official decrypting restore differs from source (err %v)", err)
		}
		blob := officialRestore(t, ref, "", "app-meta.json.blob", "epbs-enc-meta.json", "/keys/epbs-key.json", true)
		if got, _ := os.ReadFile(blob); !bytes.Equal(got, meta.Data) {
			t.Errorf("restored encrypted blob %q, want %q", got, meta.Data)
		}
		rdst := t.TempDir()
		if _, err := gopbs.Restore(ctx, gopbs.RestoreOptions{Client: epbsConfig(tokenAuth(epbsRestoreToken)), MasterKey: master, Ref: ref, Archive: "root", Target: rdst}); err != nil {
			t.Fatal(err)
		}
		sameTree(t, src, rdst)
		// Without any key the archive must not be readable.
		if _, err := gopbs.Restore(ctx, gopbs.RestoreOptions{Client: epbsConfig(tokenAuth(epbsRestoreToken)), Ref: ref, Archive: "root", Target: t.TempDir()}); err == nil {
			t.Error("restore without a key succeeded")
		}
	})

	// Exclude patterns: the official client restores exactly the expected
	// tree and the recorded .pxarexclude-cli carries the patterns.
	t.Run("exclude", func(t *testing.T) {
		opts := gopbs.BackupOptions{
			Client: epbsConfig(tokenAuth(epbsBackupToken)),
			Archive: archive.Options{Name: "root", Scan: scan.Options{
				Exclude:          strings.Fields(excludeCLIContent),
				PxarExcludeFiles: true,
			}},
			Ref:   pbs.SnapshotRef{Type: "host", ID: fmt.Sprintf("e2e-excl-%d", run)},
			Paths: []string{sourceExclDir},
		}
		res := mustBackup(t, opts)
		verifySnapshot(t, res.Ref, "")
		dst := officialRestore(t, res.Ref, "", "root.pxar", "epbs-excl", "", false)
		got := sortedKeys(treePaths(t, dst))
		want := slices.Clone(excludeFixtureRestored)
		sort.Strings(want)
		if !slices.Equal(got, want) {
			t.Errorf("restored %v\nwant %v", got, want)
		}
		if data, _ := os.ReadFile(filepath.Join(dst, ".pxarexclude-cli")); string(data) != excludeCLIContent {
			t.Errorf(".pxarexclude-cli = %q", data)
		}
	})

	// Fingerprint pinning against the real certificate.
	t.Run("fingerprint", func(t *testing.T) {
		cfg := epbsConfig(tokenAuth(epbsBackupToken))
		cfg.Fingerprint = strings.Repeat("00:", 31) + "00"
		c, err := pbs.NewClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.ListSnapshots(ctx, "host", "x"); !errors.Is(err, pbs.ErrFingerprint) {
			t.Errorf("wrong fingerprint: %v, want ErrFingerprint", err)
		}
	})
}
