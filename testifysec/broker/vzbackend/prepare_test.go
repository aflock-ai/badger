// jade:ring local
package vzbackend

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	v                    *Verifier
	install, stage, base string
	raw                  []byte
	manifest             Manifest
}

func writeTest(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}
func encodedTest(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func newFixture(t *testing.T) fixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	install := filepath.Join(base, "install")
	stage := filepath.Join(base, "stage")
	for _, p := range []string{install, stage} {
		if err = os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header, 0xfeedfacf)
	binary.LittleEndian.PutUint32(header[4:], 0x0100000c)
	binary.LittleEndian.PutUint32(header[12:], 2)
	files := [][]byte{header, []byte("kernel fixture"), []byte("root fixture"), []byte("opaque provenance fixture")}
	descriptors := make([]File, 4)
	for i, data := range files {
		descriptors[i] = File{hash(data), int64(len(data))}
	}
	m := Manifest{ManifestSchema, "darwin-vz/v1", "darwin-arm64", "linux-arm64", "testifysec.vm-job/v3", "testifysec.vm-result/v3", "HCMDL2", Files{descriptors[0], descriptors[1], descriptors[2], descriptors[3]}}
	raw := encodedTest(t, m)
	writeTest(t, filepath.Join(install, "backend.json"), raw, 0600)
	for i, r := range roles(m.Files) {
		mode := os.FileMode(0600)
		if r.executable {
			mode = 0700
		}
		writeTest(t, filepath.Join(install, r.name), files[i], mode)
	}
	a := Assignment{AssignmentSchema, install, stage, hash(raw), strings.Repeat("1", 64), filepath.Join(base, "admission"), strings.Repeat("2", 64), "tenant", "deployment", "profile"}
	v, err := New(a)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{v, install, stage, base, raw, m}
}

// This unit seam supplies validity directly. Only the separately compiled local
// UAT exercises real Rookery DSSE admission; no public API bypass exists.
func localPrepared(t *testing.T, f fixture) *Prepared {
	t.Helper()
	p, err := newStage(context.Background(), f.stage)
	if err != nil {
		t.Fatal(err)
	}
	p.notBefore = time.Now().Add(-time.Minute)
	p.expires = time.Now().Add(time.Minute)
	if err = f.v.populate(context.Background(), p); err != nil {
		_ = p.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := p.Close(); e != nil {
			t.Error(e)
		}
	})
	return p
}
func emptyStage(t *testing.T, path string) {
	t.Helper()
	files, err := os.ReadDir(path)
	if err != nil || len(files) != 0 {
		t.Fatalf("stage retained %d entries: %v", len(files), err)
	}
}

func TestPreparedCopyInspectClose(t *testing.T) {
	f := newFixture(t)
	p := localPrepared(t, f)
	observed, err := p.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if observed.ManifestSHA256 != hash(f.raw) || observed.Files != f.manifest.Files {
		t.Fatal("observation bytes not bound")
	}
	for _, r := range roles(f.manifest.Files) {
		info, e := p.root.Stat(r.name)
		if e != nil {
			t.Fatal(e)
		}
		want := os.FileMode(0400)
		if r.executable {
			want = 0500
		}
		if info.Mode().Perm() != want {
			t.Fatal("staged role is not read-only")
		}
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	emptyStage(t, f.stage)
	if _, err = p.Inspect(context.Background()); Code(err) != "prepared_closed" {
		t.Fatal("closed handle accepted", err)
	}
}
func TestPreparedFreshStages(t *testing.T) {
	f := newFixture(t)
	a := localPrepared(t, f)
	b := localPrepared(t, f)
	if a.name == b.name {
		t.Fatal("stage reused")
	}
	if e := a.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Inspect(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestPreparedExpiryAndCancellation(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		p := localPrepared(t, newFixture(t))
		p.expires = time.Now().Add(-time.Second)
		if _, e := p.Inspect(context.Background()); Code(e) != "profile_expired" {
			t.Fatal(e)
		}
	})
	t.Run("cancelled-inspect", func(t *testing.T) {
		p := localPrepared(t, newFixture(t))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, e := p.Inspect(ctx); Code(e) != "cancelled" {
			t.Fatal(e)
		}
	})
	t.Run("cancelled-prepare", func(t *testing.T) {
		f := newFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, e := f.v.Prepare(ctx, []byte("{}")); Code(e) != "cancelled" {
			t.Fatal(e)
		}
		emptyStage(t, f.stage)
	})
	t.Run("concurrent-close", func(t *testing.T) {
		p := localPrepared(t, newFixture(t))
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = p.Inspect(context.Background()) }()
		go func() {
			defer wg.Done()
			if e := p.Close(); e != nil {
				t.Error(e)
			}
		}()
		wg.Wait()
	})
}
func TestPreparedTamperRefusal(t *testing.T) {
	for _, name := range []string{"kernel", "backend.json"} {
		t.Run(name, func(t *testing.T) {
			p := localPrepared(t, newFixture(t))
			if e := p.root.Chmod(name, 0600); e != nil {
				t.Fatal(e)
			}
			file, e := p.root.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0)
			if e != nil {
				t.Fatal(e)
			}
			_, e = file.Write([]byte("tampered"))
			if e != nil {
				t.Fatal(e)
			}
			if e = file.Close(); e != nil {
				t.Fatal(e)
			}
			if _, e = p.Inspect(context.Background()); e == nil {
				t.Fatal("tampered stage accepted")
			}
		})
	}
}
func TestPartialCopyFailureCleanup(t *testing.T) {
	f := newFixture(t)
	writeTest(t, filepath.Join(f.install, "kernel"), []byte("changed fixture"), 0600)
	p, e := newStage(context.Background(), f.stage)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.v.populate(context.Background(), p); e == nil {
		t.Fatal("changed role accepted")
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	emptyStage(t, f.stage)
}
func TestCleanupRetainsUnknownContent(t *testing.T) {
	f := newFixture(t)
	p, e := newStage(context.Background(), f.stage)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.v.populate(context.Background(), p); e != nil {
		_ = p.Close()
		t.Fatal(e)
	}
	writeTest(t, filepath.Join(p.path, "unexpected"), []byte("retain"), 0600)
	if e := p.Close(); !errors.Is(e, errCleanup) {
		t.Fatal("uncertain cleanup accepted", e)
	}
	if _, e := os.Stat(filepath.Join(p.path, "unexpected")); e != nil {
		t.Fatal("unknown file removed", e)
	}
}
func TestCustodyAndInventoryRefusals(t *testing.T) {
	cases := map[string]func(*testing.T, fixture){
		"symlink-file": func(t *testing.T, f fixture) {
			if e := os.Remove(filepath.Join(f.install, "kernel")); e != nil {
				t.Fatal(e)
			}
			if e := os.Symlink("root.ext4", filepath.Join(f.install, "kernel")); e != nil {
				t.Fatal(e)
			}
		},
		"hardlink-file": func(t *testing.T, f fixture) {
			if e := os.Link(filepath.Join(f.install, "kernel"), filepath.Join(f.base, "linked")); e != nil {
				t.Fatal(e)
			}
		},
		"writable-file": func(t *testing.T, f fixture) {
			if e := os.Chmod(filepath.Join(f.install, "kernel"), 0666); e != nil {
				t.Fatal(e)
			}
		},
		"unknown-file": func(t *testing.T, f fixture) {
			writeTest(t, filepath.Join(f.install, "hc-vm-uat"), []byte("not a role"), 0600)
		},
		"missing-file": func(t *testing.T, f fixture) {
			if e := os.Remove(filepath.Join(f.install, "kernel")); e != nil {
				t.Fatal(e)
			}
		},
		"wrong-target": func(t *testing.T, f fixture) {
			raw := make([]byte, 32)
			binary.LittleEndian.PutUint32(raw, 0xfeedfacf)
			writeTest(t, filepath.Join(f.install, "hc-vm"), raw, 0700)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			mutate(t, f)
			p, e := newStage(context.Background(), f.stage)
			if e != nil {
				t.Fatal(e)
			}
			if e = f.v.populate(context.Background(), p); e == nil {
				t.Fatal("unsafe installation accepted")
			}
			if e = p.Close(); e != nil {
				t.Fatal(e)
			}
			emptyStage(t, f.stage)
		})
	}
}
func TestProtectedAncestorAndAssignment(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.base, "assignment.json")
	writeTest(t, path, encodedTest(t, f.v.assignment), 0600)
	if _, e := LoadAssignment(path); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(f.base, "alias")
	if e := os.Symlink(f.install, link); e != nil {
		t.Fatal(e)
	}
	if c, e := openCustody(link, false); e == nil {
		_ = c.close()
		t.Fatal("symlink ancestor accepted")
	}
	if e := os.Chmod(f.base, 0777); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(f.base, 0700)
	if _, e := LoadAssignment(path); e == nil {
		t.Fatal("writable ancestor accepted")
	}
}
