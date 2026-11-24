// jade:ring local
package main

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	platformsession "github.com/aflock-ai/badger/testifysec/platform"
)

// These are startup checks only. Positive identity authentication and model
// traffic are exercised by the compiled gateway/real platform handler UAT.
// Profile fields here test startup syntax only; real Rookery admission is covered
// by the separate compiled gateway profile harness.
func gatewayPlatformFixture(t *testing.T) (Config, platformsession.Config) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("startup must not pretend to authenticate a model operation")
	}))
	t.Cleanup(server.Close)
	ca := filepath.Join(root, "ca.pem")
	credential := filepath.Join(root, "credential")
	token := filepath.Join(root, "provider-token")
	for name, data := range map[string][]byte{ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), credential: []byte(strings.Repeat("a", 43)), token: []byte("synthetic-provider-token")} {
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	tenant := "11111111-1111-4111-8111-111111111111"
	agent := "22222222-2222-4222-8222-222222222222"
	binding := platformsession.Config{Endpoint: server.URL + platformsession.EndpointPath, CAFile: ca, CredentialFile: credential,
		TenantID: tenant, AgentID: agent, RepositoryID: "33333333-3333-4333-8333-333333333333", TrustDomain: "fixture.test", MinimumEnrollmentAAL: "aal2"}
	file := filepath.Join(root, "platform.json")
	data, _ := json.Marshal(binding)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(root, "spool")
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	return Config{Schema: "testifysec.hardened-opencode.gateway/v1", Socket: filepath.Join(root, "gateway.sock"), Spool: spool,
		ProviderURL: "https://provider.example/v1/chat/completions", ProviderTokenFile: token, CollectorURL: "https://collector.example/v1/logs",
		Model: "approved", Tenant: tenant, Agent: "spiffe://fixture.test/tenant/" + tenant + "/agent/" + agent, Session: "fixture-session",
		SignedProfileFile: filepath.Join(root, "profile.dsse.json"), AdmissionExecutable: filepath.Join(root, "hardened-admission"), AdmissionSHA256: strings.Repeat("b", 64),
		ProfileDigest: strings.Repeat("a", 64), MaxRecords: 4, MaxOfflineSeconds: 60, TimeoutSeconds: 10, PlatformConfigFile: file}, binding
}

func TestGatewayPlatformRequiredInProduction(t *testing.T) {
	config, _ := gatewayPlatformFixture(t)
	g, err := newGateway(config)
	if err != nil {
		t.Fatal("valid protected startup", err)
	}
	g.identity.Close()
	config.PlatformConfigFile = ""
	if _, err = newGateway(config); err == nil {
		t.Fatal("programmatic production startup bypassed platform identity")
	}
	data, _ := json.Marshal(config)
	path := filepath.Join(filepath.Dir(config.Spool), "gateway.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readConfig(path); err == nil {
		t.Fatal("production configuration bypassed platform identity")
	}
	config.DevelopmentLoopback = true
	g, err = newGateway(config)
	if err != nil {
		t.Fatal("explicit development mode must remain available", err)
	}
	if g.identity != nil {
		g.identity.Close()
		t.Fatal("development mode fabricated authenticated identity")
	}
}

func TestGatewayPlatformAssignmentAndPrivateFiles(t *testing.T) {
	for _, kind := range []string{"tenant", "spiffe", "missing-config", "public-config", "symlink-config", "missing-credential", "unknown-ca", "current-human-aal"} {
		t.Run(kind, func(t *testing.T) {
			config, binding := gatewayPlatformFixture(t)
			switch kind {
			case "tenant":
				config.Tenant = "foreign-tenant"
			case "spiffe":
				config.Agent = strings.Replace(config.Agent, "fixture.test", "foreign.test", 1)
			case "missing-config":
				config.PlatformConfigFile += ".missing"
			case "public-config":
				if err := os.Chmod(config.PlatformConfigFile, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink-config":
				link := config.PlatformConfigFile + ".link"
				if err := os.Symlink(config.PlatformConfigFile, link); err != nil {
					t.Fatal(err)
				}
				config.PlatformConfigFile = link
			case "missing-credential":
				if err := os.Remove(binding.CredentialFile); err != nil {
					t.Fatal(err)
				}
			case "unknown-ca":
				if err := os.WriteFile(binding.CAFile, []byte("not a trusted certificate"), 0600); err != nil {
					t.Fatal(err)
				}
			case "current-human-aal":
				binding.RequireCurrentHumanAAL = "aal2"
				data, _ := json.Marshal(binding)
				if err := os.WriteFile(config.PlatformConfigFile, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if g, err := newGateway(config); err == nil {
				if g.identity != nil {
					g.identity.Close()
				}
				t.Fatal("unsafe platform configuration admitted")
			}
		})
	}
}
