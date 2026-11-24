// jade:ring local
package vzsession

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func privateTestDir(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRequestCannotSupplyAuthority(t *testing.T) {
	a := Assignment{WorkspaceID: "workspace", MaximumTimeoutSeconds: 30}
	valid := `{"schema":"testifysec.aflock.vz-session-request/v1","workspaceId":"workspace","prompt":"Fix the test","timeoutSeconds":20}`
	if _, err := requestFrom([]byte(valid), a); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"tenant", "agent", "sessionId", "backend", "model", "profile", "credential", "gatewayConfigFile", "workspaceDirectory"} {
		t.Run(field, func(t *testing.T) {
			raw := strings.TrimSuffix(valid, "}") + `,"` + field + `":"chosen"}`
			if _, err := requestFrom([]byte(raw), a); err == nil {
				t.Fatal("caller gained an authority field")
			}
		})
	}
	for name, raw := range map[string]string{
		"duplicate":         strings.TrimSuffix(valid, "}") + `,"prompt":"other"}`,
		"escaped-alias":     strings.TrimSuffix(valid, "}") + `,"worksp\u0061ceId":"other"}`,
		"case-alias":        strings.Replace(valid, "workspaceId", "WorkspaceId", 1),
		"null":              strings.Replace(valid, `"Fix the test"`, `null`, 1),
		"surrogate":         strings.Replace(valid, "Fix the test", `\ud800`, 1),
		"number-rounding":   strings.Replace(valid, ":20}", ":20.00000000000000001}", 1),
		"foreign-workspace": strings.Replace(valid, `"workspace"`, `"other"`, 1),
		"timeout":           strings.Replace(valid, ":20}", ":31}", 1),
		"trailing":          valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := requestFrom([]byte(raw), a); err == nil {
				t.Fatal("ambiguous or unassigned request accepted")
			}
		})
	}
}

func TestSnapshotBindsBytesAndIgnoresGitMetadata(t *testing.T) {
	dir := privateTestDir(t)
	if err := os.WriteFile(filepath.Join(dir, "main.txt"), []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("private metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	files, err := snapshot(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "main.txt" || files[0].SHA256 != hash([]byte("original\n")) {
		t.Fatal("snapshot mismatch")
	}
	if err = os.WriteFile(filepath.Join(dir, "main.txt"), []byte("changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := base64.StdEncoding.DecodeString(files[0].ContentBase64)
	if err != nil || string(got) != "original\n" {
		t.Fatal("captured materials followed mutable workspace")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = snapshot(ctx, dir); err == nil {
		t.Fatal("cancelled snapshot accepted")
	}
}

func TestSnapshotRejectsLinksReservedPathsAndBudgets(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "windows-device", "oversize", "reserved", "privileged"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateTestDir(t)
			p := filepath.Join(dir, "file")
			if err := os.WriteFile(p, []byte("one"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink("file", filepath.Join(dir, "other"))
			case "hardlink":
				err = os.Link(p, filepath.Join(dir, "other"))
			case "windows-device":
				err = os.WriteFile(filepath.Join(dir, "NUL.txt"), []byte("reserved"), 0600)
			case "oversize":
				err = os.WriteFile(p, make([]byte, (64<<10)+1), 0600)
			case "reserved":
				err = os.Rename(p, filepath.Join(dir, "git~1"))
			case "privileged":
				err = os.Chmod(p, os.ModeSetuid|0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = snapshot(context.Background(), dir); err == nil {
				t.Fatal("unsafe workspace accepted")
			}
		})
	}
}

func TestOwnedStateRetainsUnexpectedContents(t *testing.T) {
	parent := privateTestDir(t)
	d, err := newDirectory(parent, "session")
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	if err = d.write("gateway.json", []byte("{}"), 0400); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(d.path, "unknown"), []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = d.remove(); err == nil {
		t.Fatal("unknown contents deleted")
	}
	for _, name := range []string{"gateway.json", "unknown"} {
		if _, err = os.Stat(filepath.Join(d.path, name)); err != nil {
			t.Fatal("retained file missing", name)
		}
	}
	if err = os.Remove(filepath.Join(d.path, "unknown")); err != nil {
		t.Fatal(err)
	}
	if err = d.remove(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedStateRejectsReplacedName(t *testing.T) {
	parent := privateTestDir(t)
	d, err := newDirectory(parent, "session")
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	if err = d.write("gateway.json", []byte("{}"), 0400); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(d.path, d.path+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(d.path, 0700); err != nil {
		t.Fatal(err)
	}
	if err = d.remove(); err == nil {
		t.Fatal("replaced directory accepted")
	}
	if _, err = os.Stat(d.path + "-retained/gateway.json"); err != nil {
		t.Fatal("original deleted")
	}
	if _, err = os.Stat(d.path); err != nil {
		t.Fatal("replacement deleted")
	}
}

func TestGatewayTemplateCarriesNoAuthority(t *testing.T) {
	template := gatewayTemplate{Schema: "testifysec.aflock.vz-gateway-template/v1", Protocol: "chat-completions", ProviderURL: "https://provider.example/broker/v1/chat/completions", BrokerSignIn: &brokerSignIn{EdgeURL: "https://provider.example/broker"}, CollectorURL: "https://collector.example/v1/logs", Model: "approved", MaxRecords: 10, MaxOfflineSeconds: 60, TimeoutSeconds: 30}
	if err := template.validate(); err != nil {
		t.Fatal(err)
	}
	for _, unsupported := range []string{"responses", "other-model"} {
		t.Run(unsupported, func(t *testing.T) {
			candidate := template
			if unsupported == "responses" {
				candidate.Protocol = "responses"
				candidate.ProviderURL = "https://provider.example/v1/responses"
			} else {
				candidate.Model = "other"
			}
			if err := candidate.validate(); err == nil || Code(err) != "worker_route_unsupported" {
				t.Fatal("unsupported compiled-worker route accepted")
			}
		})
	}
	raw, _ := json.Marshal(template)
	var target gatewayTemplate
	poisoned := strings.TrimSuffix(string(raw), "}") + `,"agent":"spiffe://attacker"}`
	if err := strict([]byte(poisoned), &target); err == nil {
		t.Fatal("template accepted caller identity")
	}
	template.ProviderURL = "http://127.0.0.1/v1/chat/completions"
	if err := template.validate(); err == nil {
		t.Fatal("cleartext without explicit fixture mode accepted")
	}
}

func TestAuditCustodyLossRetainsExecutionState(t *testing.T) {
	for _, target := range []string{"audit", "spool"} {
		t.Run(target, func(t *testing.T) {
			parent := privateTestDir(t)
			state, err := newDirectory(parent, "state")
			if err != nil {
				t.Fatal(err)
			}
			if err = state.write("gateway.json", []byte("{}"), 0400); err != nil {
				t.Fatal(err)
			}
			audit, err := newDirectory(parent, "audit")
			if err != nil {
				t.Fatal(err)
			}
			spool, err := newDirectory(audit.path, "spool")
			if err != nil {
				t.Fatal(err)
			}
			changed := audit
			if target == "spool" {
				changed = spool
			}
			if err = os.Rename(changed.path, changed.path+"-retained"); err != nil {
				t.Fatal(err)
			}
			if err = os.Mkdir(changed.path, 0700); err != nil {
				t.Fatal(err)
			}
			s := session{state: state, audit: audit, spool: spool}
			result := Result{AuditRetained: true}
			if err = s.finish(&result); err == nil || Code(err) != "cleanup_failed" {
				t.Fatal("lost audit custody did not refuse cleanup")
			}
			if result.StateCleaned {
				t.Fatal("state claimed clean after lost audit custody")
			}
			if _, err = os.Stat(filepath.Join(state.path, "gateway.json")); err != nil {
				t.Fatal("execution bytes deleted", err)
			}
		})
	}
}

func TestAssignmentSeparatesWorkspaceFromProtectedInputs(t *testing.T) {
	a := Assignment{Schema: AssignmentSchema, WorkspaceID: "workspace", MaximumTimeoutSeconds: 30,
		BackendAssignmentFile: "/protected/backend.json", BackendAssignmentSHA256: strings.Repeat("a", 64),
		PlatformConfigFile: "/protected/platform.json", PlatformConfigSHA256: strings.Repeat("b", 64), SignedProfileFile: "/protected/profile.json",
		GatewayExecutable: "/protected/gateway", GatewaySHA256: strings.Repeat("c", 64), GatewayTemplateFile: "/protected/template.json", GatewayTemplateSHA256: strings.Repeat("d", 64),
		WorkspaceDirectory: "/workspace", StateDirectory: "/state", AuditDirectory: "/audit"}
	if err := a.validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Assignment){
		"workspace-root":                   func(a *Assignment) { a.WorkspaceDirectory = "/" },
		"workspace-contains-configuration": func(a *Assignment) { a.WorkspaceDirectory = "/protected" },
		"state-inside-workspace":           func(a *Assignment) { a.StateDirectory = "/workspace/state" },
		"workspace-inside-state":           func(a *Assignment) { a.WorkspaceDirectory = "/state/workspace" },
		"audit-inside-state":               func(a *Assignment) { a.AuditDirectory = "/state/audit" },
		"gateway-inside-audit":             func(a *Assignment) { a.GatewayExecutable = "/audit/gateway" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := a
			change(&candidate)
			if err := candidate.validate(); err == nil {
				t.Fatal("protected input overlap accepted")
			}
		})
	}
}
