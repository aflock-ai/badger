// jade:ring local
package vzbackend

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func resultMaterial(name string, raw []byte, executable bool) RunMaterial {
	return RunMaterial{Path: name, SHA256: hash(raw), Size: int64(len(raw)), Executable: executable, ContentBase64: base64.StdEncoding.EncodeToString(raw)}
}
func resultBytes(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func observationFixture(t *testing.T) (runExpected, runObservation) {
	t.Helper()
	materials := []RunMaterial{resultMaterial("gone.txt", []byte("remove me\n"), false), resultMaterial("kept.bin", []byte{0, 255, 1}, true)}
	request := resultBytes(t, map[string]any{"prompt": "fixture task", "timeoutSeconds": 1})
	expected := runExpected{Materials: materials, InitialManifestSHA256: materialManifest(materials), KernelSHA256: strings.Repeat("c", 64), RootDiskSHA256: strings.Repeat("d", 64), GatewayConfigSHA256: strings.Repeat("e", 64)}
	expected.Binding = RunBinding{SessionID: "service-session", RequestSHA256: hash(request), ProfileSHA256: strings.Repeat("b", 64), MaterialsSHA256: hash(resultBytes(t, materials)), BackendSHA256: hash([]byte(expected.KernelSHA256 + "\n" + expected.RootDiskSHA256 + "\n"))}
	expected.JobJSON = resultBytes(t, map[string]any{"schema": "testifysec.vm-job/v3", "binding": expected.Binding, "request": json.RawMessage(request), "materials": materials})
	expected.JobSHA256 = hash(expected.JobJSON)
	files := []RunMaterial{resultMaterial("kept.bin", []byte{0, 255, 2}, true)}
	code := 0
	nonce := strings.Repeat("a", 32)
	guest := runGuestObservation{Schema: "testifysec.vm-result/v3", Nonce: nonce, JobSHA256: expected.JobSHA256, Binding: expected.Binding, JobValidated: true, Passed: true, PID: 1, WorkerUID: 65534, RootReadonly: true, WorkerStarted: true, ExitObserved: true, ExitCode: &code, Reaped: true, OutputDrained: true, OutputComplete: true, OutputBase64: base64.StdEncoding.EncodeToString([]byte("public output\n")), OutputSHA256: hash([]byte("public output\n")), CaptureComplete: true, InitialManifestSHA256: expected.InitialManifestSHA256, FinalManifestSHA256: materialManifest(files), Files: files, Removed: []string{"gone.txt"}}
	guestRaw := resultBytes(t, guest)
	serial := []byte(fmt.Sprintf("HCVM3 %08x %s\n", len(guestRaw), guestRaw))
	tail := serial
	if len(tail) > 4096 {
		tail = tail[len(tail)-4096:]
	}
	frame := runJobFrameSHA256(expected.JobJSON, nonce)
	observation := runObservation{Schema: "testifysec.vm-observation/v4", Passed: true, Started: true, Stopped: true, GuestResult: guestRaw, SerialBytes: int64(len(serial)), SerialTailBase64: base64.StdEncoding.EncodeToString(tail), ConfiguredCPUs: 1, ConfiguredMemoryMiB: 1024, JobPort: 17001, JobFrameSHA256: &frame, JobConnections: 1, JobSent: true, BootNonce: nonce, JobAdmissionClosed: true, JobTransportDrained: true, RootDiskSHA256: expected.RootDiskSHA256, JobSHA256: expected.JobSHA256, Qualification: "developer-only-unqualified", GatewayIntegrated: true, GatewayRelayDrained: true, SerialReaderDrained: true, SerialEOFObserved: true, GatewayRelay: runRelayObservation{Enabled: true, Port: 17002, Connections: 1, Forwarded: 1, AdmissionClosed: true, GatewayConfigSHA256: expected.GatewayConfigSHA256, Scope: "local-session-transport-not-model-outcome-or-signed-admission"}}
	return expected, observation
}
func changeGuest(t *testing.T, observation *runObservation, change func(*runGuestObservation)) {
	t.Helper()
	var guest runGuestObservation
	if err := json.Unmarshal(observation.GuestResult, &guest); err != nil {
		t.Fatal(err)
	}
	change(&guest)
	observation.GuestResult = resultBytes(t, guest)
}
func TestRunObservationCompleteAndFailedWorker(t *testing.T) {
	expected, observation := observationFixture(t)
	result, err := validateRunObservation(resultBytes(t, observation), expected)
	if err != nil || !result.Completed || !result.CleanupSafe {
		t.Fatal("valid complete observation refused", result, err)
	}
	t.Run("nonzero-worker-cleanup-safe", func(t *testing.T) {
		observation.Passed = false
		changeGuest(t, &observation, func(g *runGuestObservation) {
			code := 7
			g.ExitCode = &code
			g.Error = "worker-failed"
			g.Passed = false
			g.CaptureComplete = false
			g.Files = []RunMaterial{}
			g.Removed = []string{}
			g.FinalManifestSHA256 = ""
		})
		result, err := validateRunObservation(resultBytes(t, observation), expected)
		if err == nil || result.Completed || !result.CleanupSafe {
			t.Fatal("worker failure changed lifecycle truth", result, err)
		}
	})
}
func TestRunObservationStoppedWithoutGuest(t *testing.T) {
	expected, observation := observationFixture(t)
	observation.Passed = false
	observation.GuestResult = json.RawMessage(`{}`)
	reason := "gateway-relay-refused"
	observation.Error = &reason
	last := "gateway-response-truncated"
	observation.GatewayRelay.LastError = &last
	observation.GatewayRelay.TransportErrors = 1
	result, err := validateRunObservation(resultBytes(t, observation), expected)
	if err == nil || result.Completed || !result.CleanupSafe {
		t.Fatal("stopped truncated transport was not represented as failure", result, err)
	}
}
func TestRunObservationIndependentLifecycle(t *testing.T) {
	for _, field := range []string{"stopped", "job-admission", "job-drain", "relay-admission", "relay-active", "relay-drain", "serial-drain", "serial-eof"} {
		t.Run(field, func(t *testing.T) {
			expected, o := observationFixture(t)
			o.Passed = false
			switch field {
			case "stopped":
				o.Stopped = false
			case "job-admission":
				o.JobAdmissionClosed = false
			case "job-drain":
				o.JobTransportDrained = false
			case "relay-admission":
				o.GatewayRelay.AdmissionClosed = false
			case "relay-active":
				o.GatewayRelay.Active = 1
			case "relay-drain":
				o.GatewayRelayDrained = false
			case "serial-drain":
				o.SerialReaderDrained = false
			case "serial-eof":
				o.SerialEOFObserved = false
			}
			got, err := validateRunObservation(resultBytes(t, o), expected)
			if err == nil || got.Completed || got.CleanupSafe {
				t.Fatal("unproved cleanup admitted", got, err)
			}
		})
	}
}
func TestRunObservationHostMutations(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*runObservation)
	}{
		{"old-schema", func(o *runObservation) { o.Schema = "testifysec.vm-observation/v3" }},
		{"two-cpus", func(o *runObservation) { o.ConfiguredCPUs = 2 }},
		{"wrong-memory", func(o *runObservation) { o.ConfiguredMemoryMiB = 512 }},
		{"network-device", func(o *runObservation) { o.NetworkDevices = 1 }},
		{"shared-directory", func(o *runObservation) { o.SharedDirectories = 1 }},
		{"writable-disk", func(o *runObservation) { o.WritableHostDisks = 1 }},
		{"wrong-job-port", func(o *runObservation) { o.JobPort = 17002 }},
		{"wrong-model-port", func(o *runObservation) { o.GatewayRelay.Port = 17001 }},
		{"wrong-root", func(o *runObservation) { o.RootDiskSHA256 = strings.Repeat("f", 64) }},
		{"wrong-job", func(o *runObservation) { o.JobSHA256 = strings.Repeat("f", 64) }},
		{"wrong-frame", func(o *runObservation) { value := strings.Repeat("f", 64); o.JobFrameSHA256 = &value }},
		{"missing-frame", func(o *runObservation) { o.JobFrameSHA256 = nil }},
		{"wrong-nonce", func(o *runObservation) { o.BootNonce = strings.Repeat("f", 32) }},
		{"bad-nonce", func(o *runObservation) { o.BootNonce = "ABC" }},
		{"wrong-gateway", func(o *runObservation) { o.GatewayRelay.GatewayConfigSHA256 = strings.Repeat("f", 64) }},
		{"gateway-disabled", func(o *runObservation) { o.GatewayIntegrated = false }},
		{"relay-disabled", func(o *runObservation) { o.GatewayRelay.Enabled = false }},
		{"invented-admission", func(o *runObservation) { o.AdmissionIntegrated = true }},
		{"invented-qualification", func(o *runObservation) { o.Qualification = "production" }},
		{"bad-relay-scope", func(o *runObservation) { o.GatewayRelay.Scope = "authorized" }},
		{"negative-connections", func(o *runObservation) { o.GatewayRelay.Connections = -1 }},
		{"excess-connections", func(o *runObservation) { o.GatewayRelay.Connections = 33 }},
		{"excess-forwarded", func(o *runObservation) { o.GatewayRelay.Forwarded = 2 }},
		{"overlapping-early-complete", func(o *runObservation) { o.GatewayRelay.EarlyGatewayRefusals = 1 }},
		{"phantom-error", func(o *runObservation) { v := "failed"; o.GatewayRelay.LastError = &v }},
		{"unreported-error", func(o *runObservation) { o.GatewayRelay.TransportErrors = 1 }},
		{"negative-serial", func(o *runObservation) { o.SerialBytes = -1 }},
		{"bad-tail", func(o *runObservation) { o.SerialTailBase64 = "?" }},
		{"short-serial", func(o *runObservation) { o.SerialBytes = 1 }},
		{"job-not-started", func(o *runObservation) { o.Started = false }},
		{"no-job-connection", func(o *runObservation) { o.JobConnections = 0 }},
		{"null-guest", func(o *runObservation) { o.GuestResult = json.RawMessage(`null`) }},
		{"empty-success-guest", func(o *runObservation) { o.GuestResult = json.RawMessage(`{}`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expected, o := observationFixture(t)
			tc.mutate(&o)
			got, err := validateRunObservation(resultBytes(t, o), expected)
			if err == nil || got.Completed || got.CleanupSafe {
				t.Fatal("modified host claim admitted", got, err)
			}
		})
	}
}
func TestRunObservationGuestMutations(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*runGuestObservation)
	}{
		{"old-schema", func(g *runGuestObservation) { g.Schema = "testifysec.vm-result/v2" }},
		{"wrong-session", func(g *runGuestObservation) { g.Binding.SessionID = "other" }},
		{"wrong-profile", func(g *runGuestObservation) { g.Binding.ProfileSHA256 = strings.Repeat("f", 64) }},
		{"wrong-request", func(g *runGuestObservation) { g.Binding.RequestSHA256 = strings.Repeat("f", 64) }},
		{"wrong-materials", func(g *runGuestObservation) { g.Binding.MaterialsSHA256 = strings.Repeat("f", 64) }},
		{"wrong-backend", func(g *runGuestObservation) { g.Binding.BackendSHA256 = strings.Repeat("f", 64) }},
		{"wrong-nonce", func(g *runGuestObservation) { g.Nonce = strings.Repeat("f", 32) }},
		{"wrong-job", func(g *runGuestObservation) { g.JobSHA256 = strings.Repeat("f", 64) }},
		{"wrong-pid", func(g *runGuestObservation) { g.PID = 2 }},
		{"root-worker", func(g *runGuestObservation) { g.WorkerUID = 0 }},
		{"exit-not-observed", func(g *runGuestObservation) { g.ExitObserved = false }},
		{"null-exit", func(g *runGuestObservation) { g.ExitCode = nil }},
		{"exit-range", func(g *runGuestObservation) { v := 256; g.ExitCode = &v }},
		{"bad-output-hash", func(g *runGuestObservation) { g.OutputSHA256 = strings.Repeat("f", 64) }},
		{"bad-output-base64", func(g *runGuestObservation) { g.OutputBase64 += "\n" }},
		{"no-reap", func(g *runGuestObservation) { g.Reaped = false }},
		{"no-output-drain", func(g *runGuestObservation) { g.OutputDrained = false }},
		{"output-incomplete", func(g *runGuestObservation) { g.OutputComplete = false }},
		{"root-writable", func(g *runGuestObservation) { g.RootReadonly = false }},
		{"unstarted-worker", func(g *runGuestObservation) { g.WorkerStarted = false }},
		{"wrong-initial", func(g *runGuestObservation) { g.InitialManifestSHA256 = strings.Repeat("f", 64) }},
		{"wrong-final", func(g *runGuestObservation) { g.FinalManifestSHA256 = strings.Repeat("f", 64) }},
		{"tampered-file", func(g *runGuestObservation) {
			g.Files[0].ContentBase64 = base64.StdEncoding.EncodeToString([]byte("tampered"))
		}},
		{"executable-intent", func(g *runGuestObservation) { g.Files[0].Executable = false }},
		{"wrong-removal", func(g *runGuestObservation) { g.Removed = []string{"kept.bin"} }},
		{"duplicate-removal", func(g *runGuestObservation) { g.Removed = []string{"gone.txt", "gone.txt"} }},
		{"lost-removal", func(g *runGuestObservation) { g.Removed = []string{} }},
		{"absolute-path", func(g *runGuestObservation) { g.Files[0].Path = "/escape" }},
		{"git-path", func(g *runGuestObservation) { g.Files[0].Path = ".git/config" }},
		{"null-files", func(g *runGuestObservation) { g.Files = nil }},
		{"incomplete-with-files", func(g *runGuestObservation) { g.CaptureComplete = false; g.Passed = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expected, o := observationFixture(t)
			changeGuest(t, &o, tc.mutate)
			got, err := validateRunObservation(resultBytes(t, o), expected)
			if err == nil || got.Completed || got.CleanupSafe {
				t.Fatal("modified guest claim admitted", got, err)
			}
		})
	}
}
func TestRunObservationStrictWire(t *testing.T) {
	expected, o := observationFixture(t)
	raw := resultBytes(t, o)
	cases := map[string][]byte{
		"duplicate":         append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"passed":true}`)...),
		"escaped-duplicate": bytes.Replace(raw, []byte(`"passed":true`), []byte(`"pass\u0065d":true,"passed":true`), 1),
		"case-alias":        bytes.Replace(raw, []byte(`"serialEOFObserved":`), []byte(`"SerialEOFObserved":`), 1),
		"null-bool":         bytes.Replace(raw, []byte(`"serialEOFObserved":true`), []byte(`"serialEOFObserved":null`), 1),
		"decimal":           bytes.Replace(raw, []byte(`"configuredCPUs":1`), []byte(`"configuredCPUs":1.0`), 1),
		"exponent":          bytes.Replace(raw, []byte(`"configuredCPUs":1`), []byte(`"configuredCPUs":1e0`), 1),
		"negative-zero":     bytes.Replace(raw, []byte(`"networkDevices":0`), []byte(`"networkDevices":-0`), 1),
		"unknown":           append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"identity":"trusted"}`)...),
		"trailing":          append(append([]byte{}, raw...), []byte(`{}`)...),
		"surrogate":         bytes.Replace(raw, []byte(`"error":null`), []byte(`"error":"\ud800"`), 1),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, value) {
				t.Fatal("mutation did not change bytes")
			}
			got, err := validateRunObservation(value, expected)
			if err == nil || got.Completed || got.CleanupSafe {
				t.Fatal("ambiguous wire admitted", got, err)
			}
		})
	}
}
func TestRunJobFrameFoundationVector(t *testing.T) {
	// Observed with real Foundation JSONSerialization(sortedKeys): schema slash
	// and all four base64 slashes are escaped in the original wire bytes.
	got := runJobFrameSHA256([]byte{255, 255, 255}, strings.Repeat("a", 32))
	if got != "520f907bed8afdcf15f3ccff000e8edea9765b6cd50a6bbdd0f69e247ed888b4" {
		t.Fatal("Foundation frame serialization differs", got)
	}
}

func TestRunObservationNullRemovalWithNoChanges(t *testing.T) {
	expected, o := observationFixture(t)
	changeGuest(t, &o, func(g *runGuestObservation) {
		g.Files = expected.Materials
		g.FinalManifestSHA256 = expected.InitialManifestSHA256
		g.Removed = []string{}
	})
	if got, err := validateRunObservation(resultBytes(t, o), expected); err != nil || !got.Completed {
		t.Fatal("valid no-removal control refused", got, err)
	}
	changeGuest(t, &o, func(g *runGuestObservation) { g.Removed = nil })
	if got, err := validateRunObservation(resultBytes(t, o), expected); err == nil || got.CleanupSafe {
		t.Fatal("null removal accepted", got, err)
	}
}
func TestRunObservationExpectedJobMismatch(t *testing.T) {
	for _, name := range []string{"binding", "material", "job-digest", "initial-manifest"} {
		t.Run(name, func(t *testing.T) {
			expected, o := observationFixture(t)
			switch name {
			case "binding":
				expected.Binding.RequestSHA256 = strings.Repeat("f", 64)
			case "material":
				expected.Materials[0].Executable = true
			case "job-digest":
				expected.JobSHA256 = strings.Repeat("f", 64)
			case "initial-manifest":
				expected.InitialManifestSHA256 = strings.Repeat("f", 64)
			}
			if got, err := validateRunObservation(resultBytes(t, o), expected); err == nil || got.CleanupSafe {
				t.Fatal("mismatched service job accepted", got, err)
			}
		})
	}
}
