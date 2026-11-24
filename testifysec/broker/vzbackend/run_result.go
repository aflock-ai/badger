package vzbackend

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
)

type runRelayObservation struct {
	Enabled               bool    `json:"enabled"`
	Port                  int     `json:"port"`
	Connections           int     `json:"connections"`
	Forwarded             int     `json:"forwarded"`
	TransportErrors       int     `json:"transportErrors"`
	EarlyGatewayRefusals  int     `json:"earlyGatewayRefusals"`
	ResponseCancellations int     `json:"responseCancellations"`
	AdmissionClosed       bool    `json:"admissionClosed"`
	Active                int     `json:"active"`
	GatewayConfigSHA256   string  `json:"gatewayConfigSha256"`
	LastError             *string `json:"lastError"`
	Scope                 string  `json:"scope"`
}
type runObservation struct {
	Schema                          string              `json:"schema"`
	Passed                          bool                `json:"passed"`
	Started                         bool                `json:"started"`
	Stopped                         bool                `json:"stopped"`
	Error                           *string             `json:"error"`
	GuestResult                     json.RawMessage     `json:"guestResult"`
	SerialBytes                     int64               `json:"serialBytes"`
	SerialTailBase64                string              `json:"serialTailBase64"`
	ConfiguredCPUs                  int                 `json:"configuredCPUs"`
	ConfiguredMemoryMiB             int                 `json:"configuredMemoryMiB"`
	NetworkDevices                  int                 `json:"networkDevices"`
	SharedDirectories               int                 `json:"sharedDirectories"`
	WritableHostDisks               int                 `json:"writableHostDisks"`
	JobPort                         int                 `json:"jobPort"`
	JobFrameSHA256                  *string             `json:"jobFrameSha256"`
	JobConnections                  int                 `json:"jobConnections"`
	JobSent                         bool                `json:"jobSent"`
	BootNonce                       string              `json:"bootNonce"`
	JobAdmissionClosed              bool                `json:"jobAdmissionClosed"`
	JobTransportDrained             bool                `json:"jobTransportDrained"`
	JobConnectionsRefusedAfterClose int64               `json:"jobConnectionsRefusedAfterClose"`
	RootDiskSHA256                  string              `json:"rootDiskSha256"`
	JobSHA256                       string              `json:"jobSha256"`
	Qualification                   string              `json:"qualification"`
	AdmissionIntegrated             bool                `json:"admissionIntegrated"`
	GatewayIntegrated               bool                `json:"gatewayIntegrated"`
	GatewayRelay                    runRelayObservation `json:"gatewayRelay"`
	GatewayRelayDrained             bool                `json:"gatewayRelayDrained"`
	SerialReaderDrained             bool                `json:"serialReaderDrained"`
	SerialEOFObserved               bool                `json:"serialEOFObserved"`
}
type runGuestObservation struct {
	Schema                string        `json:"schema"`
	Nonce                 string        `json:"nonce"`
	JobSHA256             string        `json:"jobSha256"`
	Binding               RunBinding    `json:"binding"`
	JobValidated          bool          `json:"jobValidated"`
	Passed                bool          `json:"passed"`
	Error                 string        `json:"error"`
	PID                   int           `json:"pid"`
	WorkerUID             uint32        `json:"workerUid"`
	RootReadonly          bool          `json:"rootReadonly"`
	WorkerStarted         bool          `json:"workerStarted"`
	ExitObserved          bool          `json:"exitObserved"`
	ExitCode              *int          `json:"exitCode"`
	Reaped                bool          `json:"reaped"`
	OutputDrained         bool          `json:"outputDrained"`
	OutputComplete        bool          `json:"outputComplete"`
	OutputBase64          string        `json:"outputBase64"`
	OutputSHA256          string        `json:"outputSha256"`
	CaptureComplete       bool          `json:"captureComplete"`
	InitialManifestSHA256 string        `json:"initialManifestSha256"`
	FinalManifestSHA256   string        `json:"finalManifestSha256"`
	Files                 []RunMaterial `json:"files"`
	Removed               []string      `json:"removed"`
}

func canonicalBase64(value string, limit int) ([]byte, bool) {
	if len(value) > base64.StdEncoding.EncodedLen(limit) {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	return decoded, err == nil && len(decoded) <= limit && base64.StdEncoding.EncodeToString(decoded) == value
}
func runErrorCode(value *string) bool {
	if value == nil {
		return true
	}
	if len(*value) < 1 || len(*value) > 256 {
		return false
	}
	for _, r := range *value {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

// Foundation's sortedKeys JSONSerialization escapes forward slashes. Both the
// envelope schema and base64 job can contain them. Bind the complete wire frame,
// including its version magic and big-endian length, rather than only its body.
func runJobFrameSHA256(job []byte, nonce string) string {
	raw, _ := json.Marshal(map[string]string{"jobBase64": base64.StdEncoding.EncodeToString(job), "nonce": nonce, "schema": "testifysec.vm-envelope/v3"})
	raw = []byte(strings.ReplaceAll(string(raw), "/", `\/`))
	if len(raw) > runJobLimit*2 {
		return ""
	}
	frame := make([]byte, 12, 12+len(raw))
	copy(frame, []byte("HCJOB3\r\n"))
	// Each masked octet is representable without a narrowing length cast.
	for index := 0; index < 4; index++ {
		frame[8+index] = byte((len(raw) >> (24 - 8*index)) & 0xff)
	}
	return hash(append(frame, raw...))
}
func validRunExpected(expected runExpected) bool {
	if !validExpectedJob(expected) {
		return false
	}
	return len(expected.JobJSON) > 0 && len(expected.JobJSON) <= runJobLimit && hash(expected.JobJSON) == expected.JobSHA256 &&
		hexDigest.MatchString(expected.KernelSHA256) && hexDigest.MatchString(expected.RootDiskSHA256) &&
		hexDigest.MatchString(expected.GatewayConfigSHA256) && hexDigest.MatchString(expected.Binding.ProfileSHA256) &&
		hexDigest.MatchString(expected.Binding.RequestSHA256) && hexDigest.MatchString(expected.Binding.MaterialsSHA256) &&
		expected.Binding.BackendSHA256 == hash([]byte(expected.KernelSHA256+"\n"+expected.RootDiskSHA256+"\n")) &&
		validateMaterials(expected.Materials) == nil && materialManifest(expected.Materials) == expected.InitialManifestSHA256
}

// Cross-check the service-generated job as original bytes as well as its
// digest. This prevents a mismatched expected tuple from weakening validation.
func validExpectedJob(expected runExpected) bool {
	if len(expected.Binding.SessionID) > 64 || !identifier.MatchString(expected.Binding.SessionID) {
		return false
	}
	var job struct {
		Schema    string          `json:"schema"`
		Binding   RunBinding      `json:"binding"`
		Request   json.RawMessage `json:"request"`
		Materials json.RawMessage `json:"materials"`
	}
	if strictVM(expected.JobJSON, &job) != nil || job.Schema != "testifysec.vm-job/v3" || job.Binding != expected.Binding ||
		hash(job.Request) != expected.Binding.RequestSHA256 || hash(job.Materials) != expected.Binding.MaterialsSHA256 {
		return false
	}
	var materials []RunMaterial
	return strictVM(job.Materials, &materials) == nil && slices.Equal(materials, expected.Materials)
}

func validRunRelay(relay runRelayObservation, expected runExpected) bool {
	if !relay.Enabled || relay.Port != 17002 || relay.Scope != "local-session-transport-not-model-outcome-or-signed-admission" ||
		relay.GatewayConfigSHA256 != expected.GatewayConfigSHA256 || relay.Connections < 0 || relay.Connections > 32 || relay.Active < 0 || relay.Active > 2 || relay.Active > relay.Connections || !runErrorCode(relay.LastError) {
		return false
	}
	for _, count := range []int{relay.Forwarded, relay.TransportErrors, relay.EarlyGatewayRefusals, relay.ResponseCancellations} {
		if count < 0 || count > relay.Connections {
			return false
		}
	}
	return relay.Forwarded+relay.EarlyGatewayRefusals <= relay.Connections && (relay.TransportErrors == 0) == (relay.LastError == nil)
}
func validHostResources(o runObservation) bool {
	return o.Schema == "testifysec.vm-observation/v4" && o.ConfiguredCPUs == 1 && o.ConfiguredMemoryMiB == 1024 &&
		o.NetworkDevices == 0 && o.SharedDirectories == 0 && o.WritableHostDisks == 0 && o.JobPort == 17001 &&
		o.Qualification == "developer-only-unqualified" && !o.AdmissionIntegrated && o.GatewayIntegrated
}
func validHostBindings(o runObservation, e runExpected) bool {
	return o.RootDiskSHA256 == e.RootDiskSHA256 && o.JobSHA256 == e.JobSHA256 &&
		len(o.BootNonce) == 32 && strings.Trim(o.BootNonce, "0123456789abcdef") == ""
}
func validHostCounts(o runObservation) bool {
	return o.JobConnections >= 0 && o.JobConnections <= 1 && o.JobConnectionsRefusedAfterClose >= 0 &&
		o.JobConnectionsRefusedAfterClose <= 9007199254740991 && o.SerialBytes >= 0 && o.SerialBytes <= 9007199254740991
}
func validHostJobFrame(o runObservation, e runExpected) bool {
	if o.JobFrameSHA256 != nil && *o.JobFrameSHA256 != runJobFrameSHA256(e.JobJSON, o.BootNonce) {
		return false
	}
	return !o.JobSent || o.Started && o.JobConnections == 1 && o.JobFrameSHA256 != nil
}
func validRunHeader(o runObservation, e runExpected) bool {
	if !validHostResources(o) || !validHostBindings(o, e) || !validHostCounts(o) ||
		!runErrorCode(o.Error) || !validRunRelay(o.GatewayRelay, e) || !validHostJobFrame(o, e) {
		return false
	}
	tail, ok := canonicalBase64(o.SerialTailBase64, 4096)
	return ok && int64(len(tail)) <= o.SerialBytes
}
func validGuestProcess(g runGuestObservation) bool {
	if g.PID != 1 || g.WorkerUID != 65534 || len(g.Error) > 256 || g.ExitObserved != (g.ExitCode != nil) {
		return false
	}
	return g.ExitCode == nil || (*g.ExitCode >= -1 && *g.ExitCode <= 255)
}
func guestCompleteState(g runGuestObservation) bool {
	return g.JobValidated && g.RootReadonly && g.WorkerStarted && g.ExitObserved && g.ExitCode != nil && *g.ExitCode == 0 &&
		g.Reaped && g.OutputDrained && g.OutputComplete
}
func removedMaterials(initial, final []RunMaterial) []string {
	retained := make(map[string]bool, len(final))
	for _, file := range final {
		retained[file.Path] = true
	}
	removed := []string{}
	for _, file := range initial {
		if !retained[file.Path] {
			removed = append(removed, file.Path)
		}
	}
	return removed
}
func validGuestCapture(g runGuestObservation, e runExpected) bool {
	if !g.CaptureComplete {
		return len(g.Files) == 0 && len(g.Removed) == 0 && g.FinalManifestSHA256 == ""
	}
	if !guestCompleteState(g) || g.InitialManifestSHA256 != e.InitialManifestSHA256 || g.FinalManifestSHA256 != materialManifest(g.Files) {
		return false
	}
	return slices.Equal(g.Removed, removedMaterials(e.Materials, g.Files))
}
func validRunGuest(g runGuestObservation, e runExpected, nonce string) bool {
	if g.Removed == nil || g.Schema != "testifysec.vm-result/v3" || g.Nonce != nonce || g.Binding != e.Binding || g.JobSHA256 != e.JobSHA256 ||
		!validGuestProcess(g) || validateMaterials(g.Files) != nil || !validGuestCapture(g, e) {
		return false
	}
	output, ok := canonicalBase64(g.OutputBase64, 64<<10)
	return ok && hash(output) == g.OutputSHA256 && g.Passed == (g.Error == "" && g.CaptureComplete)
}
func checkedRunGuest(o runObservation, e runExpected) (bool, error) {
	invalid := refused("run_observation_invalid")
	var shape map[string]json.RawMessage
	if json.Unmarshal(o.GuestResult, &shape) != nil || shape == nil {
		return false, invalid
	}
	if len(shape) == 0 {
		return false, nil
	}
	var guest runGuestObservation
	if len(o.GuestResult) > 768<<10 || strictVM(o.GuestResult, &guest) != nil || !validRunGuest(guest, e, o.BootNonce) || !o.JobSent {
		return false, invalid
	}
	return guest.Passed && guest.JobValidated, nil
}
func runCleanupObserved(o runObservation) bool {
	return o.Stopped && o.JobAdmissionClosed && o.JobTransportDrained && o.GatewayRelayDrained &&
		o.GatewayRelay.AdmissionClosed && o.GatewayRelay.Active == 0 && o.SerialReaderDrained && o.SerialEOFObserved
}
func runCompletionObserved(o runObservation, guestPassed bool) bool {
	return o.Started && o.JobSent && runCleanupObserved(o) && o.Error == nil && o.GatewayRelay.TransportErrors == 0 && guestPassed
}

// Parse the original host bytes without weakening the nested v3 contract. Host
// lifecycle and guest success are independent: a failed worker can have safely
// stopped, while malformed claims never authorize cleanup. Process exit, both
// process-output EOFs and group absence are separate checks by the Run caller.
func validateRunObservation(raw []byte, expected runExpected) (runLifecycle, error) {
	invalid := refused("run_observation_invalid")
	if len(raw) == 0 || len(raw) > runObservationLimit || !validRunExpected(expected) {
		return runLifecycle{}, invalid
	}
	var observation runObservation
	if strictVM(raw, &observation) != nil || !validRunHeader(observation, expected) {
		return runLifecycle{}, invalid
	}
	guestPassed, err := checkedRunGuest(observation, expected)
	if err != nil {
		return runLifecycle{}, err
	}
	cleanup := runCleanupObserved(observation)
	completed := runCompletionObserved(observation, guestPassed)
	if observation.Passed != completed {
		return runLifecycle{}, invalid
	}
	lifecycle := runLifecycle{Completed: completed, CleanupSafe: cleanup}
	if !completed {
		return lifecycle, refused("run_incomplete")
	}
	return lifecycle, nil
}
