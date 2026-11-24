// Command portal-uat-fixtures signs profiles through the portal's own issuer and writes them,
// with the trust input the portal exports, for portal/uat.py to feed the compiled native
// admission. Keys are ephemeral and live only in memory.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/aflock-ai/badger/testifysec/portal/internal/issue"
	"github.com/aflock-ai/badger/testifysec/portal/internal/sign"
	"github.com/aflock-ai/badger/testifysec/portal/internal/store"
)

type nop struct{}

// memProfiles is a ProfileStore in memory: the fixtures need signed envelopes, not a database.
type memProfiles struct{ vs []store.Version }

func (m *memProfiles) Put(v store.Version) error {
	for _, x := range m.vs {
		if x.ProfileID == v.ProfileID && x.Sequence == v.Sequence {
			return store.ErrExists
		}
	}
	m.vs = append(m.vs, v)
	return nil
}

func (m *memProfiles) Latest(id string) (store.Version, bool, error) {
	var best store.Version
	found := false
	for _, x := range m.vs {
		if x.ProfileID == id && (!found || x.Sequence > best.Sequence) {
			best, found = x, true
		}
	}
	return best, found, nil
}

func (m *memProfiles) Versions(id string) ([]store.Version, error) {
	var out []store.Version
	for _, x := range m.vs {
		if x.ProfileID == id {
			out = append(out, x)
		}
	}
	return out, nil
}

func (m *memProfiles) Get(id string, seq uint64) (store.Version, bool, error) {
	for _, x := range m.vs {
		if x.ProfileID == id && x.Sequence == seq {
			return x, true, nil
		}
	}
	return store.Version{}, false, nil
}

func (m *memProfiles) List() ([]store.Version, error) { return m.vs, nil }

func (nop) Append(store.Record) error { return nil }

func issuer(tmp string) *issue.Issuer {
	files := &memProfiles{}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	key, err := sign.NewKey(ec)
	if err != nil {
		log.Fatal(err)
	}
	return &issue.Issuer{TenantID: "uat-tenant", MinimumSequence: 10, Signers: []sign.Signer{key},
		Profiles: files, Audit: nop{}, Now: time.Now}
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: portal-uat-fixtures OUTPUT")
	}
	out := os.Args[1]
	tmp, err := os.MkdirTemp("", "portal-uat-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	now := time.Now().UTC().Truncate(time.Second)
	req := func(profileID, deployment string) issue.Request {
		return issue.Request{ProfileID: profileID, DeploymentID: deployment,
			NotBefore: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(7 * 24 * time.Hour).Format(time.RFC3339)}
	}
	portal, other := issuer(tmp), issuer(tmp)
	mustIssue := func(i *issue.Issuer, r issue.Request) store.Version {
		v, err := i.Issue("CN=UAT Admin", "admin", r)
		if err != nil {
			log.Fatal(err)
		}
		return v
	}
	previous := mustIssue(portal, req("uat-managed", "uat-deployment"))
	current := mustIssue(portal, req("uat-managed", "uat-deployment"))
	wrongDeployment := mustIssue(portal, req("uat-elsewhere", "uat-other-deployment"))
	wrongKey := mustIssue(other, req("uat-managed", "uat-deployment"))
	tampered := bytes.Replace(current.Envelope, []byte(`"payload":"`), []byte(`"payload":"A`), 1)
	if err = os.MkdirAll(out, 0o700); err != nil {
		log.Fatal(err)
	}
	write := func(name string, raw []byte) {
		if err := os.WriteFile(filepath.Join(out, name), raw, 0o600); err != nil {
			log.Fatal(err)
		}
	}
	trust, _ := json.Marshal(portal.Trust(current))
	write("trust.json", trust)
	for name, v := range map[string]store.Version{"current": current, "previous": previous,
		"wrong-deployment": wrongDeployment, "wrong-key": wrongKey} {
		write(name+".json", v.Envelope)
		v.Envelope = nil
		meta, _ := json.Marshal(v)
		write(name+".version.json", meta)
	}
	write("tampered.json", tampered)
}
