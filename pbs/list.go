package pbs

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"time"
)

// SnapshotInfo is one entry of ListSnapshots.
type SnapshotInfo struct {
	Ref       SnapshotRef
	Size      uint64 // as the server reports it
	Files     []string
	Protected bool
	// Encrypted reports that at least one file has crypt-mode "encrypt":
	// reading it needs Config.Crypt (or a master key).
	Encrypted bool
	Comment   string // the first line of the snapshot notes
}

// Datastore is one entry of ListDatastores.
type Datastore struct {
	Name    string
	Comment string
}

// Namespace is one entry of ListNamespaces.
type Namespace struct {
	Path    string // full path, "a/b"
	Comment string
}

// Group is one entry of ListGroups: a backup type and id.
type Group struct {
	Type       string
	ID         string
	LastBackup time.Time
	Count      int
	Owner      string
	Comment    string
	Files      []string // of the newest snapshot
}

// datastorePath is the admin API path of the configured datastore.
func (c *Client) datastorePath(op, sub string) (string, error) {
	if c.cfg.Datastore == "" {
		return "", fmt.Errorf("pbs: %s requires Config.Datastore", op)
	}
	return "/api2/json/admin/datastore/" + url.PathEscape(c.cfg.Datastore) + "/" + sub, nil
}

// nsQuery returns the query selecting the configured namespace.
func (c *Client) nsQuery() url.Values {
	q := url.Values{}
	if c.cfg.Namespace != "" {
		q.Set("ns", c.cfg.Namespace)
	}
	return q
}

// ListDatastores returns the datastores the credentials can access, sorted
// by name. Config.Datastore is not used.
func (c *Client) ListDatastores(ctx context.Context) ([]Datastore, error) {
	var data []struct {
		Store   string `json:"store"`
		Comment string `json:"comment"`
	}
	if err := c.do(ctx, "GET", "/api2/json/admin/datastore", "listing datastores", nil, true, &data); err != nil {
		return nil, err
	}
	out := make([]Datastore, 0, len(data))
	for _, d := range data {
		out = append(out, Datastore{Name: d.Store, Comment: d.Comment})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ListNamespaces returns the direct child namespaces of Config.Namespace in
// Config.Datastore, sorted by path.
func (c *Client) ListNamespaces(ctx context.Context) ([]Namespace, error) {
	path, err := c.datastorePath("listing namespaces", "namespace")
	if err != nil {
		return nil, err
	}
	q := url.Values{"max-depth": {"1"}}
	if c.cfg.Namespace != "" {
		q.Set("parent", c.cfg.Namespace)
	}
	var data []struct {
		NS      string `json:"ns"`
		Comment string `json:"comment"`
	}
	if err := c.do(ctx, "GET", path, "listing namespaces", q, true, &data); err != nil {
		return nil, err
	}
	out := make([]Namespace, 0, len(data))
	for _, d := range data {
		if d.NS != c.cfg.Namespace { // the server includes the parent itself
			out = append(out, Namespace{Path: d.NS, Comment: d.Comment})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// ListGroups returns the backup groups in Config.Namespace of
// Config.Datastore, sorted by type and id.
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	path, err := c.datastorePath("listing groups", "groups")
	if err != nil {
		return nil, err
	}
	var data []struct {
		Type    string   `json:"backup-type"`
		ID      string   `json:"backup-id"`
		Last    int64    `json:"last-backup"`
		Count   int      `json:"backup-count"`
		Owner   string   `json:"owner"`
		Comment string   `json:"comment"`
		Files   []string `json:"files"`
	}
	if err := c.do(ctx, "GET", path, "listing groups", c.nsQuery(), true, &data); err != nil {
		return nil, err
	}
	out := make([]Group, 0, len(data))
	for _, d := range data {
		out = append(out, Group{Type: d.Type, ID: d.ID, LastBackup: time.Unix(d.Last, 0),
			Count: d.Count, Owner: d.Owner, Comment: d.Comment, Files: d.Files})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// ListSnapshots returns one backup group's snapshots, newest first.
// backupType "" means "host". The token needs Datastore.Audit or
// Datastore.Backup.
func (c *Client) ListSnapshots(ctx context.Context, backupType, backupID string) ([]SnapshotInfo, error) {
	path, err := c.datastorePath("listing snapshots", "snapshots")
	if err != nil {
		return nil, err
	}
	if backupType == "" {
		backupType = "host"
	}
	if backupID == "" {
		return nil, fmt.Errorf("pbs: listing snapshots requires a backup id")
	}
	query := c.nsQuery()
	query.Set("backup-type", backupType)
	query.Set("backup-id", backupID)

	var data []struct {
		BackupType string `json:"backup-type"`
		BackupID   string `json:"backup-id"`
		BackupTime int64  `json:"backup-time"`
		Size       uint64 `json:"size"`
		Protected  bool   `json:"protected"`
		Comment    string `json:"comment"`
		Files      []struct {
			Filename  string `json:"filename"`
			CryptMode string `json:"crypt-mode"`
		} `json:"files"`
	}
	if err := c.do(ctx, "GET", path, "listing snapshots", query, true, &data); err != nil {
		return nil, err
	}

	out := make([]SnapshotInfo, 0, len(data))
	for _, d := range data {
		// Not every server implementation honours the query filter.
		if d.BackupType != backupType || d.BackupID != backupID {
			continue
		}
		info := SnapshotInfo{
			Ref:       SnapshotRef{Type: d.BackupType, ID: d.BackupID, Time: time.Unix(d.BackupTime, 0)},
			Size:      d.Size,
			Protected: d.Protected,
			Comment:   d.Comment,
		}
		for _, f := range d.Files {
			info.Files = append(info.Files, f.Filename)
			info.Encrypted = info.Encrypted || f.CryptMode == string(CryptModeEncrypt)
		}
		out = append(out, info)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Ref.Time.After(out[j].Ref.Time) })
	return out, nil
}
