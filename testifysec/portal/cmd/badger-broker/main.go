// Command badger-broker is Badger's model broker and management portal as one service: the
// broker's model listeners, its provisioning listener, and one admin listener that serves the
// broker's admin API and the portal behind one IdP admin check. See
// testifysec/model-broker/README.md and testifysec/PORTAL.md.
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	broker "github.com/aflock-ai/badger/testifysec/model-broker"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/portal/internal/auth"
	"github.com/aflock-ai/badger/testifysec/portal/internal/issue"
	"github.com/aflock-ai/badger/testifysec/portal/internal/profile"
	"github.com/aflock-ai/badger/testifysec/portal/internal/sign"
	"github.com/aflock-ai/badger/testifysec/portal/internal/store"
	"github.com/aflock-ai/badger/testifysec/portal/internal/users"
	"github.com/aflock-ai/badger/testifysec/portal/internal/web"
)

// portalConfig is the "portal" section of the service's configuration. Unknown fields are refused.
type portalConfig struct {
	// SigningKeyFile is the profile signing key, mounted from the key vault.
	SigningKeyFile  string `json:"signing_key_file"`
	TenantID        string `json:"tenant_id"`
	MinimumSequence uint64 `json:"minimum_sequence"`
	// Bootstrap gives these IdP subjects a role only until a provisioned user holds it, so the
	// first admin and approver can grant real roles. It is never the directory.
	Bootstrap map[string]auth.Role `json:"bootstrap"`
	// ImportDataDir is a portal data directory from before the database (profiles, assignments,
	// audit log, users, role requests, bootstrap markers), imported once into an empty database
	// at start. Required when import_state_dir moves the broker's state.
	ImportDataDir string `json:"import_data_dir,omitempty"`
	// Import "none" declares there is no portal data to import (the portal never ran file-backed
	// here): import_state_dir moves the broker's state alone, and the declaration is recorded as
	// the portal's import. The only value; never together with ImportDataDir.
	Import string `json:"import,omitempty"`
	// DataDir is refused: the portal's state is in the database now.
	DataDir string `json:"data_dir,omitempty"`
}

func parsePortal(raw json.RawMessage) (portalConfig, error) {
	var c portalConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("config: portal: %w", err)
	}
	if c.DataDir != "" {
		return c, errors.New("config: portal.data_dir is gone: the portal's state is in the database; " +
			"set portal.import_data_dir to that directory once to import it")
	}
	if c.Import != "" && c.Import != "none" {
		return c, fmt.Errorf(`config: portal.import takes "none" only, not %q`, c.Import)
	}
	if c.Import == "none" && c.ImportDataDir != "" {
		return c, errors.New(`config: portal.import "none" says there is no portal data; it cannot be set with portal.import_data_dir`)
	}
	if c.SigningKeyFile == "" {
		return c, errors.New("config: portal.signing_key_file is required")
	}
	if !profile.ValidIdentifier(c.TenantID) || c.MinimumSequence < 1 || c.MinimumSequence > profile.MaxSequence {
		return c, errors.New("config: portal.tenant_id must be an identifier and portal.minimum_sequence 1..2^53-1")
	}
	seen := map[auth.Role]bool{}
	for subject, role := range c.Bootstrap {
		if role != auth.Admin && role != auth.Approver {
			return c, fmt.Errorf("config: portal.bootstrap: unknown role %q for %q", role, subject)
		}
		if seen[role] {
			return c, fmt.Errorf("config: portal.bootstrap: more than one %s", role)
		}
		seen[role] = true
	}
	return c, nil
}

// service is every listener's handler, built once.
type service struct {
	internal, edge, provision, admin http.Handler
}

// build opens the broker on db and, when configured, the portal it mounts on the admin listener
// at /admin/portal. The portal and its signing key are reachable from nowhere else.
func build(cfg *broker.FileConfig, db *sql.DB) (*service, error) {
	b := broker.Open(cfg, db)
	s := &service{internal: b.Internal(), edge: b.Edge(), provision: b.Provision()}
	if len(cfg.Portal) == 0 {
		s.admin = b.Admin()
		return s, nil
	}
	pc, err := parsePortal(cfg.Portal)
	if err != nil {
		return nil, err
	}
	// The portal's state moves with the broker's: its bootstrap markers are what keep a retired
	// bootstrap subject from getting its role back.
	if cfg.ImportStateDir != "" && pc.ImportDataDir == "" && pc.Import != "none" {
		return nil, errors.New(`config: import_state_dir moves the broker's state; set portal.import_data_dir to the portal's data directory too, ` +
			`or portal.import "none" if this deployment's portal never kept data in files`)
	}
	if pc.Import == "none" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		recorded, err := users.DeclareNoImport(ctx, db, cfg.Ceiling())
		cancel()
		if err != nil {
			return nil, err
		}
		if recorded {
			log.Printf("portal import: %s", users.NoImport)
		}
	}
	if pc.ImportDataDir != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		rep, err := users.ImportFiles(ctx, db, cfg.Ceiling(), pc.ImportDataDir)
		cancel()
		if err != nil {
			return nil, err
		}
		if rep.Imported {
			log.Printf("imported portal state from %s: %s", pc.ImportDataDir, rep)
		}
	}
	key, err := sign.LoadKeyFile(pc.SigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("portal signing key: %w", err)
	}
	// Admin sessions run at the deployment's ceiling.
	profiles := store.NewPG(db, cfg.Ceiling())
	if err := profiles.Verify(); err != nil {
		return nil, fmt.Errorf("portal: %w", err)
	}
	// The portal knows a person only through the broker's admin check: the IdP subject of
	// someone the edge signed in with an admin group.
	identify := func(r *http.Request) (users.Identity, error) {
		id, _, ok := b.AdminIdentity(r)
		if !ok {
			return users.Identity{}, errors.New("no verified admin identity")
		}
		return users.Identity{Kind: users.KindIdP, Subject: id}, nil
	}
	people := &users.Service{Store: users.NewPG(db, cfg.Ceiling()), Audit: profiles, Identify: identify, Bootstrap: pc.Bootstrap, Now: time.Now}
	srv := &web.Server{Auth: people, Users: people, Profiles: profiles, Origins: cfg.AllowedOrigins, Issuer: &issue.Issuer{
		TenantID: pc.TenantID, MinimumSequence: pc.MinimumSequence, Signers: []sign.Signer{key},
		Profiles: profiles, Assignments: profiles, Audit: profiles, Now: time.Now}}
	s.admin = b.Admin(broker.Mount{Prefix: "/admin/portal", Handler: srv.Handler()})
	log.Printf("portal: tenant %s, signing key %s, on the admin listener at /admin/portal", pc.TenantID, key.KeyID())
	return s, nil
}

// components is the whole schema, in migration order.
var components = []pgdb.Component{pgdb.Core, broker.Schema, store.Schema}

// openDatabase migrates the schema with the owner role when one is configured, connects as the
// service role and checks every migration is there, and imports a file-backed broker state
// directory once if one is named.
// plaintextHost names hosts reached without TLS beyond loopback: none. Tests set it to their
// scratch Postgres (BADGER_TEST_PG), which is never the service's configuration.
var plaintextHost func(host string) bool

func openDatabase(ctx context.Context, cfg *broker.FileConfig) (*sql.DB, error) {
	read := func(path string) (string, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", errors.New("database: cannot read a connection string file")
		}
		return strings.TrimSpace(string(raw)), nil
	}
	if cfg.Database.OwnerDSNFile != "" {
		dsn, err := read(cfg.Database.OwnerDSNFile)
		if err != nil {
			return nil, err
		}
		if err := pgdb.RequireTLS(dsn, plaintextHost); err != nil {
			return nil, err
		}
		owner, err := pgdb.Open(ctx, dsn)
		if err != nil {
			return nil, err
		}
		err = pgdb.Migrate(ctx, owner, cfg.Database.ServiceRole, components...)
		owner.Close()
		if err != nil {
			return nil, err
		}
	}
	dsn, err := read(cfg.Database.DSNFile)
	if err != nil {
		return nil, err
	}
	if err := pgdb.RequireTLS(dsn, plaintextHost); err != nil {
		return nil, err
	}
	db, err := pgdb.Open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	// The service connection is the service role and nothing more, checked before anything is read.
	if err := pgdb.CheckService(ctx, db, cfg.Database.ServiceRole); err != nil {
		db.Close()
		return nil, err
	}
	if err := pgdb.Check(ctx, db, components...); err != nil {
		db.Close()
		return nil, err
	}
	if cfg.ImportStateDir != "" {
		rep, err := broker.ImportState(ctx, db, cfg, cfg.ImportStateDir)
		if err != nil {
			db.Close()
			return nil, err
		}
		if rep.Imported {
			log.Printf("imported broker state from %s: %s", cfg.ImportStateDir, rep)
		}
	}
	return db, nil
}

func main() {
	path := flag.String("config", "/etc/badger-broker/config.json", "operator configuration file")
	flag.Parse()
	cfg, err := broker.LoadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}
	db, err := openDatabase(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	s, err := build(cfg, db)
	if err != nil {
		log.Fatal(err)
	}
	servers := []*http.Server{
		{Addr: cfg.Listen.Internal, Handler: s.internal},
		{Addr: cfg.Listen.Edge, Handler: s.edge},
		{Addr: cfg.Listen.Provision, Handler: s.provision},
		{Addr: cfg.Listen.Admin, Handler: s.admin},
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	failed := make(chan error, len(servers))
	for _, srv := range servers {
		srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout = 10*time.Second, 15*time.Second, cfg.ServerWriteTimeout()
		srv.IdleTimeout, srv.MaxHeaderBytes = 60*time.Second, 32<<10
		go func() { failed <- srv.ListenAndServe() }()
	}
	select {
	case err := <-failed:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Print("listener failed")
			os.Exit(1)
		}
	case <-ctx.Done():
		drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, srv := range servers {
			if srv.Shutdown(drain) != nil {
				srv.Close()
			}
		}
	}
}
