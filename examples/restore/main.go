// Command restore restores an archive from Proxmox Backup Server into a
// directory with a single gopbs.Restore call: the newest snapshot of the
// backup group by default, the whole archive or only the -path entries,
// v1 or v2 (told apart by the snapshot manifest). With -list it prints the
// archive's tree instead, without reading any file content.
//
// Encrypted backups need -keyfile (passphrase from PBS_ENCRYPTION_PASSWORD
// for a protected key), or -master-key, the RSA master private key, whose
// passphrase is read from PBS_MASTER_PASSWORD.
//
// The flag defaults match the test stack in tests/compose.yml:
//
//	cd tests && docker compose up -d garage pmoxs3
//	go run ./examples/backup-sync -source /tmp
//	go run ./examples/restore -id "$(hostname)" -list
//	go run ./examples/restore -id "$(hostname)" -target /tmp/restored
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/catalog"
	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/restore"
)

func main() {
	var (
		url         = flag.String("url", "https://localhost:8007", "PBS base URL")
		username    = flag.String("username", "garagegarage", "user name (without realm)")
		realm       = flag.String("realm", "pbs", "authentication realm")
		password    = flag.String("password", "garagegaragegarage", "password")
		fingerprint = flag.String("fingerprint", "55:BC:29:4B:BA:B6:A1:03:42:A9:D8:51:14:9D:BD:00:D2:2A:9C:A1:B8:4A:85:E1:AF:B2:0C:48:40:D6:CC:A4", "server certificate SHA-256 fingerprint")
		datastore   = flag.String("datastore", "pbs", "datastore name")
		backupID    = flag.String("id", "", "backup id (default: hostname)")
		snapshot    = flag.Int64("time", 0, "snapshot time as a Unix timestamp (default: newest)")
		name        = flag.String("name", "root", "archive name, as given to the backup")
		target      = flag.String("target", "", "directory to restore into (missing or empty)")
		overwrite   = flag.Bool("overwrite", false, "allow a target with content")
		list        = flag.Bool("list", false, "print the archive tree instead of restoring")
		keyFile     = flag.String("keyfile", "", "encryption key file (key.json)")
		masterKey   = flag.String("master-key", "", "RSA master private key (PEM) to recover the encryption key with")
		paths       []string
	)
	flag.Func("path", "archive path to restore, with its subtree (repeatable; default: everything)", func(p string) error {
		paths = append(paths, p)
		return nil
	})
	flag.Parse()
	if *target == "" && !*list {
		flag.Usage()
		os.Exit(2)
	}

	cfg := pbs.Config{
		BaseURL:     *url,
		Auth:        pbs.PasswordAuth{Username: *username, Realm: *realm, Password: *password},
		Fingerprint: *fingerprint,
		Datastore:   *datastore,
	}
	if *keyFile != "" {
		data, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatal(err)
		}
		info, err := pbs.LoadKeyFile(data, passphrase("PBS_ENCRYPTION_PASSWORD"))
		if err != nil {
			log.Fatal(err)
		}
		cfg.Crypt = info.CryptConfig(pbs.CryptModeEncrypt)
	}
	opts := gopbs.RestoreOptions{
		Client:  cfg,
		Ref:     pbs.SnapshotRef{Type: "host", ID: *backupID},
		Archive: *name,
		Target:  *target,
		Paths:   paths,
		Restore: restore.Options{
			Overwrite: *overwrite,
			OnWarn:    func(w restore.Warning) { fmt.Fprintf(os.Stderr, "warning: %v\n", w) },
		},
	}
	if *snapshot != 0 {
		opts.Ref.Time = time.Unix(*snapshot, 0)
	}
	if *masterKey != "" {
		data, err := os.ReadFile(*masterKey)
		if err != nil {
			log.Fatal(err)
		}
		if opts.MasterKey, err = pbs.LoadMasterKey(data, passphrase("PBS_MASTER_PASSWORD")); err != nil {
			log.Fatal(err)
		}
	}
	ctx := context.Background()

	if *list {
		sess, err := gopbs.OpenSnapshot(ctx, opts.Client, opts.Ref, opts.MasterKey)
		if err != nil {
			log.Fatal(err)
		}
		defer sess.Close()
		tree, err := gopbs.Browse(ctx, sess, *name)
		if err != nil {
			log.Fatal(err)
		}
		printTree(tree, "")
		return
	}

	started := time.Now()
	res, err := gopbs.Restore(ctx, opts)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("restored %s from %s/%s/%s (v%d) into %s in %.1fs, %d warnings\n",
		*name, res.Ref.Type, res.Ref.ID, res.Ref.Time.UTC().Format(time.RFC3339), int(res.Format)+1,
		*target, time.Since(started).Seconds(), len(res.Warnings))
}

// passphrase reads a passphrase from the environment; unset means none.
func passphrase(env string) []byte {
	if v, ok := os.LookupEnv(env); ok {
		return []byte(v)
	}
	return nil
}

func printTree(e *catalog.Entry, indent string) {
	switch e.Type {
	case catalog.TypeFile:
		fmt.Printf("%s%s  %d bytes  %s\n", indent, e.Name, e.Size, time.Unix(e.MtimeSecs, 0).Format(time.DateTime))
	case catalog.TypeDirectory:
		fmt.Printf("%s%s/\n", indent, e.Name)
	default:
		fmt.Printf("%s%s  (%c)\n", indent, e.Name, e.Type)
	}
	for _, c := range e.Children {
		printTree(c, indent+strings.Repeat(" ", 2))
	}
}
