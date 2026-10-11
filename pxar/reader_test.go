package pxar_test

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/osshield/gopbs/pxar"
)

const (
	modeDir     = 0o040000
	modeRegular = 0o100000
)

// dirRecords encodes a directory body: entry, the children (each a
// filename followed by its records) and a goodbye table. The reader does
// not interpret goodbye tables, so an empty one serves.
func dirRecords(mode uint64, children ...[]byte) []byte {
	b := pxar.AppendEntry(nil, pxar.Entry{Mode: modeDir | mode})
	for _, c := range children {
		b = append(b, c...)
	}
	return pxar.AppendGoodbye(b, nil, 0, uint64(len(b)))
}

func child(name string, records ...[]byte) []byte {
	return append(pxar.AppendFilename(nil, name), bytes.Join(records, nil)...)
}

func regular(content string) []byte {
	b := pxar.AppendEntry(nil, pxar.Entry{Mode: modeRegular | 0o644})
	return append(pxar.AppendPayloadHeader(b, uint64(len(content))), content...)
}

func readAll(t *testing.T, r *pxar.Reader) (nodes []*pxar.Node, contents map[string]string) {
	t.Helper()
	contents = map[string]string{}
	for {
		n, err := r.Next()
		if err == io.EOF {
			return nodes, contents
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, n)
		contents[n.Path] = string(data)
	}
}

// Every record type decodes into the matching Node field.
func TestReaderAllRecords(t *testing.T) {
	groupObj := uint64(5)
	acl := &pxar.ACLs{
		Users:         []pxar.ACLUser{{UID: 1000, Permissions: 6}},
		Groups:        []pxar.ACLGroup{{GID: 100, Permissions: 4}},
		GroupObj:      &groupObj,
		Default:       &pxar.ACLDefault{UserObjPermissions: 7, GroupObjPermissions: 5, OtherPermissions: 0, MaskPermissions: pxar.ACLNoMask},
		DefaultUsers:  []pxar.ACLUser{{UID: 1001, Permissions: 7}},
		DefaultGroups: []pxar.ACLGroup{{GID: 101, Permissions: 5}},
	}
	fileEntry := pxar.Entry{Mode: modeRegular | 0o640, UID: 1000, GID: 100, MtimeSecs: -5, MtimeNanos: 9}
	var meta []byte
	meta = pxar.AppendEntry(meta, fileEntry)
	meta = pxar.AppendXAttr(meta, "user.a", []byte("v\x00w"))
	meta = pxar.AppendACLUser(meta, acl.Users[0])
	meta = pxar.AppendACLGroup(meta, acl.Groups[0])
	meta = pxar.AppendACLGroupObj(meta, groupObj)
	meta = pxar.AppendACLDefault(meta, *acl.Default)
	meta = pxar.AppendACLDefaultUser(meta, acl.DefaultUsers[0])
	meta = pxar.AppendACLDefaultGroup(meta, acl.DefaultGroups[0])
	meta = pxar.AppendFCaps(meta, []byte{1, 2, 3})
	meta = pxar.AppendQuotaProjID(meta, 7)

	archive := dirRecords(0o755,
		child("dev", pxar.AppendEntry(nil, pxar.Entry{Mode: 0o020600}), pxar.AppendDevice(nil, pxar.Device{Major: 1, Minor: 3})),
		child("fifo", pxar.AppendEntry(nil, pxar.Entry{Mode: 0o010644})),
		child("file", meta, pxar.AppendPayloadHeader(nil, 5), []byte("hello")),
		child("hl", pxar.AppendHardlink(nil, 99, "file")),
		child("link", pxar.AppendEntry(nil, pxar.Entry{Mode: 0o120777}), pxar.AppendSymlink(nil, "../elsewhere")),
		child("sub", dirRecords(0o700, child("inner", regular("")))),
	)

	nodes, contents := readAll(t, pxar.NewReaderV1(bytes.NewReader(archive)))
	want := []*pxar.Node{
		{Path: "", Entry: pxar.Entry{Mode: modeDir | 0o755}},
		{Path: "dev", Entry: pxar.Entry{Mode: 0o020600}, Device: pxar.Device{Major: 1, Minor: 3}},
		{Path: "fifo", Entry: pxar.Entry{Mode: 0o010644}},
		{Path: "file", Entry: fileEntry, Xattrs: []pxar.Xattr{{Name: "user.a", Value: []byte("v\x00w")}},
			ACL: acl, FCaps: []byte{1, 2, 3}, QuotaProjID: 7, Size: 5},
		{Path: "hl", Hardlink: true, LinkTarget: "file"},
		{Path: "link", Entry: pxar.Entry{Mode: 0o120777}, LinkTarget: "../elsewhere"},
		{Path: "sub", Entry: pxar.Entry{Mode: modeDir | 0o700}},
		{Path: "sub/inner", Entry: pxar.Entry{Mode: modeRegular | 0o644}},
	}
	if !reflect.DeepEqual(nodes, want) {
		for i := range max(len(nodes), len(want)) {
			if i >= len(nodes) || i >= len(want) || !reflect.DeepEqual(nodes[i], want[i]) {
				t.Fatalf("node %d:\n got  %+v\n want %+v", i, at(nodes, i), at(want, i))
			}
		}
	}
	if contents["file"] != "hello" || contents["sub/inner"] != "" || contents["dev"] != "" {
		t.Fatalf("contents %q", contents)
	}
}

func at(nodes []*pxar.Node, i int) any {
	if i < len(nodes) {
		return *nodes[i]
	}
	return nil
}

// Unread content is skipped by Next.
func TestReaderSkipsUnreadContent(t *testing.T) {
	archive := dirRecords(0o755, child("a", regular("aaaa")), child("b", regular("bb")))
	r := pxar.NewReaderV1(bytes.NewReader(archive))
	var paths []string
	for {
		n, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, n.Path)
		if n.Path == "a" {
			buf := make([]byte, 1)
			if _, err := r.Read(buf); err != nil || buf[0] != 'a' {
				t.Fatalf("partial read: %q %v", buf, err)
			}
		}
	}
	if strings.Join(paths, ",") != ",a,b" {
		t.Fatalf("paths %q", paths)
	}
}

func v2Archive(content string) (meta, payload []byte) {
	meta = pxar.AppendFormatVersion(nil, 2)
	meta = pxar.AppendPrelude(meta, []byte("*.tmp\n"))
	f := pxar.AppendEntry(nil, pxar.Entry{Mode: modeRegular | 0o644})
	f = pxar.AppendPayloadRef(f, pxar.MarkerSize, uint64(len(content)))
	meta = append(meta, dirRecords(0o755, child("f", f))...)

	payload = pxar.AppendPayloadStartMarker(nil)
	payload = pxar.AppendPayloadHeader(payload, uint64(len(content)))
	payload = append(payload, content...)
	payload = pxar.AppendPayloadTailMarker(payload)
	return meta, payload
}

func TestReaderV2(t *testing.T) {
	meta, payload := v2Archive("split content")
	nodes, contents := readAll(t, pxar.NewReaderV2(bytes.NewReader(meta), bytes.NewReader(payload)))
	if len(nodes) != 2 || nodes[1].PayloadOffset != pxar.MarkerSize || contents["f"] != "split content" {
		t.Fatalf("nodes %+v contents %q", nodes, contents)
	}

	// Metadata only: entries decode, content does not.
	r := pxar.NewReaderV2(bytes.NewReader(meta), nil)
	r.Next()
	if n, err := r.Next(); err != nil || n.Size != 13 {
		t.Fatalf("metadata-only: %+v %v", n, err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("content read without a payload stream")
	}
}

func TestReaderRejects(t *testing.T) {
	v1 := func(children ...[]byte) []byte { return dirRecords(0o755, children...) }
	v2meta, v2payload := v2Archive("hello")

	deep := regular("x")
	for range 2049 {
		deep = child("d", dirRecords(0o755, deep))
	}

	badACL := pxar.AppendEntry(nil, pxar.Entry{Mode: modeRegular})
	badACL = append(badACL, pxar.AppendACLGroupObj(nil, 1)[:8]...)
	badACL = append(badACL, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

	bigXattr := pxar.AppendEntry(nil, pxar.Entry{Mode: modeRegular})
	bigXattr = pxar.AppendXAttr(bigXattr, "user.big", make([]byte, 2<<20))

	truncated := v1(child("f", regular("hello")))
	truncated = truncated[:bytes.Index(truncated, []byte("hello"))+2]

	shortPayload := append([]byte(nil), v2payload...)
	shortPayload = shortPayload[:len(shortPayload)-pxar.MarkerSize-2]

	for _, tc := range []struct {
		name          string
		meta, payload []byte
		v2            bool
		want          string
	}{
		{"dot-dot name", v1(child("..", regular("x"))), nil, false, "invalid filename"},
		{"slash in name", v1(child("a/b", regular("x"))), nil, false, "contains '/'"},
		{"hardlink escaping", v1(child("h", pxar.AppendHardlink(nil, 1, "../etc/passwd"))), nil, false, "invalid filename"},
		{"absolute hardlink", v1(child("h", pxar.AppendHardlink(nil, 1, "/etc/passwd"))), nil, false, "empty filename"},
		{"empty symlink", v1(child("l", pxar.AppendEntry(nil, pxar.Entry{Mode: 0o120777}), pxar.AppendSymlink(nil, ""))), nil, false, "empty target"},
		{"truncated content", truncated, nil, false, "unexpected EOF"},
		{"trailing data", append(v1(), 0), nil, false, "trailing data"},
		{"bad ACL length", v1(child("f", badACL)), nil, false, "has length"},
		{"oversized record", v1(child("f", bigXattr)), nil, false, "too large"},
		{"too deep", v1(deep), nil, false, "nests deeper"},
		{"v2 stream, v1 reader", v2meta, nil, false, "v2 metadata stream"},
		{"v1 stream, v2 reader", v1(), v2payload, true, "not a v2 metadata stream"},
		{"payload too short", v2meta, shortPayload, true, "unexpected EOF"},
		{"no payload start marker", v2meta, v2payload[pxar.MarkerSize:], true, "start marker"},
		{"ref size mismatch", bytes.Replace(v2meta, []byte{5, 0, 0, 0, 0, 0, 0, 0}, []byte{4, 0, 0, 0, 0, 0, 0, 0}, 1), v2payload, true, "does not resolve"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r *pxar.Reader
			if tc.v2 {
				r = pxar.NewReaderV2(bytes.NewReader(tc.meta), bytes.NewReader(tc.payload))
			} else {
				r = pxar.NewReaderV1(bytes.NewReader(tc.meta))
			}
			var err error
			for err == nil {
				if _, err = r.Next(); err == nil {
					_, err = io.Copy(io.Discard, r)
				}
			}
			if errors.Is(err, io.EOF) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if _, again := r.Next(); again == nil || again.Error() != err.Error() {
				t.Fatalf("error not sticky: %v then %v", err, again)
			}
		})
	}
}
