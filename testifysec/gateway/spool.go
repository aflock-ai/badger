package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

type Record struct {
	ID                string    `json:"id"`
	Tenant            string    `json:"tenant"`
	Session           string    `json:"session"`
	Agent             string    `json:"agent"`
	ProfileDigest     string    `json:"profileDigest"`
	Model             string    `json:"model"`
	Started           time.Time `json:"started"`
	Finished          time.Time `json:"finished"`
	Outcome           string    `json:"outcome"`
	Status            int       `json:"status"`
	RequestBytes      int       `json:"requestBytes"`
	ResponseBytes     int64     `json:"responseBytes"`
	IdentitySource    string    `json:"identitySource"`
	IdentityCheckedAt time.Time `json:"identityCheckedAt"`
	RepositoryID      string    `json:"repositoryId"`
	DelegatingUserID  string    `json:"delegatingUserId"`
	EnrollmentAAL     string    `json:"enrollmentAal"`
}

type Spool struct {
	mu      sync.Mutex
	config  Config
	records map[string]Record
	fault   error
}

func openSpool(c Config) (*Spool, error) {
	if err := privateDirectory(c.Spool); err != nil {
		return nil, err
	}
	s, err := os.Lstat(c.Spool)
	if err != nil || !s.IsDir() || s.Mode().Perm() != 0700 {
		return nil, errors.New("private spool directory required")
	}
	d, err := os.Open(c.Spool)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	entries, err := d.Readdirnames(c.MaxRecords + 2)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > c.MaxRecords+1 {
		return nil, errors.New("spool capacity exceeded")
	}
	a := &Spool{config: c, records: map[string]Record{}}
	for _, name := range entries {
		if regexp.MustCompile(`^\.pending-[0-9]+$`).MatchString(name) {
			// An uncommitted initial write cannot have admitted a provider call.
			// An uncommitted terminal write leaves its original start intact.
			// Discard only our bounded private regular temporary file, under the
			// daemon's exclusive spool lock. Never follow or remove a link.
			path := filepath.Join(c.Spool, name)
			if _, err := privateFile(path, 4096); err != nil {
				return nil, err
			}
			if err := os.Remove(path); err != nil {
				return nil, err
			}
			if err := d.Sync(); err != nil {
				return nil, err
			}
			continue
		}
		if len(name) != 37 || filepath.Ext(name) != ".json" {
			return nil, errors.New("unexpected spool entry")
		}
		b, err := privateFile(filepath.Join(c.Spool, name), 4096)
		if err != nil {
			return nil, err
		}
		var r Record
		if err = strictJSON(b, &r); err != nil {
			return nil, err
		}
		id, err := hex.DecodeString(r.ID)
		if err != nil || len(id) != 16 || name != r.ID+".json" || r.Tenant != c.Tenant || r.Session != c.Session || r.Agent != c.Agent || r.ProfileDigest != c.ProfileDigest || r.Model != c.Model && !reModelID.MatchString(r.Model) || r.Started.IsZero() {
			return nil, errors.New("invalid spool binding")
		}
		if r.Outcome == "started" {
			r.Outcome = "incomplete-after-restart"
			r.Finished = time.Now().UTC()
			if err = a.persist(r); err != nil {
				return nil, err
			}
		}
		a.records[r.ID] = r
	}
	if len(a.records) > c.MaxRecords {
		return nil, errors.New("spool capacity exceeded")
	}
	return a, nil
}

// Both the file and its directory reach stable storage before admission returns.
// A failed terminal write leaves the original start record for crash recovery.
func (s *Spool) persist(r Record) error {
	b, err := json.Marshal(r)
	if err != nil || len(b) > 4096 {
		return errors.New("invalid audit record")
	}
	f, err := os.CreateTemp(s.config.Spool, ".pending-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, filepath.Join(s.config.Spool, r.ID+".json")); err != nil {
		return err
	}
	d, err := os.Open(s.config.Spool)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Spool) begin(bytes int) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fault != nil || len(s.records) >= s.config.MaxRecords {
		return Record{}, errors.New("audit unavailable")
	}
	now := time.Now().UTC()
	for _, r := range s.records {
		if now.Sub(r.Started) > time.Duration(s.config.MaxOfflineSeconds)*time.Second {
			return Record{}, errors.New("audit too old")
		}
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Record{}, err
	}
	r := Record{ID: hex.EncodeToString(id[:]), Tenant: s.config.Tenant, Session: s.config.Session, Agent: s.config.Agent, ProfileDigest: s.config.ProfileDigest, Model: s.config.Model, Started: now, Outcome: "started", RequestBytes: bytes, IdentitySource: "administrator-provisioned"}
	if err := s.persist(r); err != nil {
		s.fault = err
		return Record{}, err
	}
	s.records[r.ID] = r
	return r, nil
}

// Preserve the platform-checked attribution durably before the provider side
// effect; a crash cannot leave only the pre-authentication start record.
func (s *Spool) attribute(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fault != nil {
		return errors.New("audit unavailable")
	}
	if _, ok := s.records[r.ID]; !ok {
		return errors.New("unknown request")
	}
	if err := s.persist(r); err != nil {
		s.fault = err
		return err
	}
	s.records[r.ID] = r
	return nil
}

func (s *Spool) finish(r Record, outcome string, status int, responseBytes int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Finished = time.Now().UTC()
	r.Outcome = outcome
	r.Status = status
	r.ResponseBytes = responseBytes
	if err := s.persist(r); err != nil {
		s.fault = err
		return err
	}
	s.records[r.ID] = r
	return nil
}

func (s *Spool) next() (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for id, r := range s.records {
		if r.Outcome != "started" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return Record{}, false
	}
	return s.records[ids[0]], true
}

func (s *Spool) acknowledge(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[id]; !ok {
		return fmt.Errorf("unknown audit id")
	}
	if err := os.Remove(filepath.Join(s.config.Spool, id+".json")); err != nil {
		s.fault = err
		return err
	}
	d, err := os.Open(s.config.Spool)
	if err != nil {
		s.fault = err
		return err
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		s.fault = err
		return err
	}
	delete(s.records, id)
	return nil
}
