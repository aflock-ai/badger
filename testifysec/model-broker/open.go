package broker

import (
	"database/sql"
	"log"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// bottomBanner is the lowest label, a workspace's when the provisioner names none.
var bottomBanner = marking.Banner(marking.Marking{})

// Open opens the broker on db, which the owner has migrated (Schema). A store that fails its
// checks, or a seed policy it cannot load, is logged and leaves every pipeline denied until an
// admin repairs it. Every listener runs its transactions at the deployment's ceiling except a
// workspace's own requests, which run at the workspace's label.
func Open(cfg *FileConfig, db *sql.DB) *Broker {
	op := cfg.Operator()
	store := OpenStore(db, cfg.Ceiling(), op)
	if store.broken != nil {
		log.Printf("policy store refused: %v; every pipeline is denied until it is repaired", store.broken)
	} else if err := store.Seed(op, cfg.SeedPolicyFile, time.Now()); err != nil {
		log.Printf("seed policy not loaded: %v; every pipeline is denied until an admin writes a policy", err)
	}
	if v := store.Active(); v != nil {
		log.Printf("policy version %d active (%d entries)", v.N, len(v.Entries))
	} else {
		log.Printf("no active policy: every pipeline is denied")
	}
	return newBroker(cfg, db, store, nil)
}
