package vzbackend

import "time"

// RunRequest is assembled by the protected session service, never decoded from
// a worker-selected execution configuration. NotAfter only narrows timing; it
// is not authentication evidence or an authorization grant. It bounds launch
// freshness only; the worker timeout and host stop deadline bound execution.
type RunRequest struct {
	SessionID           string
	Prompt              string
	TimeoutSeconds      int
	Materials           []RunMaterial
	GatewayConfigFile   string
	GatewayConfigSHA256 string
	NotAfter            time.Time
}
type RunMaterial struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	Executable    bool   `json:"executable"`
	ContentBase64 string `json:"contentBase64"`
}
type RunBinding struct {
	RequestSHA256   string `json:"requestSha256"`
	ProfileSHA256   string `json:"profileSha256"`
	SessionID       string `json:"sessionId"`
	MaterialsSHA256 string `json:"materialsSha256"`
	BackendSHA256   string `json:"backendSha256"`
}
type RunResult struct {
	Schema                string     `json:"schema"`
	Completed             bool       `json:"completed"`
	CleanupSafe           bool       `json:"cleanupSafe"`
	HostInvoked           bool       `json:"hostInvoked"`
	ObservationJSON       []byte     `json:"observationBase64,omitempty"`
	ObservationSHA256     string     `json:"observationSha256,omitempty"`
	JobJSON               []byte     `json:"jobBase64,omitempty"`
	JobSHA256             string     `json:"jobSha256,omitempty"`
	Binding               RunBinding `json:"binding"`
	ProfileSHA256         string     `json:"profileSha256"`
	BackendManifestSHA256 string     `json:"backendManifestSha256"`
	GatewayConfigSHA256   string     `json:"gatewayConfigSha256"`
	ConfigSHA256          string     `json:"configSha256,omitempty"`
	InitialManifestSHA256 string     `json:"initialManifestSha256,omitempty"`
	HostExitObserved      bool       `json:"hostExitObserved"`
	HostExitCode          *int       `json:"hostExitCode"`
	HostStdoutEOF         bool       `json:"hostStdoutEOF"`
	HostStderrEOF         bool       `json:"hostStderrEOF"`
	HostGroupAbsent       bool       `json:"hostGroupAbsent"`
	StartedAt             time.Time  `json:"startedAt"`
	FinishedAt            time.Time  `json:"finishedAt"`
}
type runExpected struct {
	Binding               RunBinding
	JobSHA256             string
	JobJSON               []byte
	InitialManifestSHA256 string
	Materials             []RunMaterial
	KernelSHA256          string
	RootDiskSHA256        string
	GatewayConfigSHA256   string
}
type runLifecycle struct{ Completed, CleanupSafe bool }

const runJobLimit = 512 << 10
const runObservationLimit = 2 << 20
const runMaterialLimit = 256 << 10
const runFileLimit = 64 << 10
const runFilesLimit = 128
const runEntriesLimit = 256
