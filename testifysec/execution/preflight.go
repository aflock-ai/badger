// Package execution reports local VM prerequisites. It does not execute code.
package execution

import (
	"runtime"
	"time"
)

type State string

const (
	Available   State = "available"
	Unavailable State = "unavailable"
	Unknown     State = "unknown"
)

// Observation describes a local API result, not authenticated evidence or a
// durable authorization. Available applies only to the named check.
type Observation struct {
	ID     string `json:"id"`
	State  State  `json:"state"`
	Method string `json:"method"`
	Detail string `json:"detail"`
}

type Target struct {
	OS                   string `json:"os"`
	Arch                 string `json:"arch"`
	ProposedBackend      string `json:"proposedBackend"`
	BackendImplemented   bool   `json:"backendImplemented"`
	BackendRuntimeTested bool   `json:"backendRuntimeTested"`
	Qualification        string `json:"qualification"`
}

type Report struct {
	Schema           string        `json:"schema"`
	ObservedAt       string        `json:"observedAt"`
	Target           Target        `json:"target"`
	TargetProposed   bool          `json:"targetProposed"`
	Prerequisites    State         `json:"observedPrerequisites"`
	Observations     []Observation `json:"observations"`
	ExecutionAllowed bool          `json:"executionAllowed"`
	RefusalReasons   []string      `json:"refusalReasons"`
	EvidenceScope    string        `json:"evidenceScope"`
}

type executionRefusal string

func (err executionRefusal) Error() string { return string(err) }

const errExecutionUnavailable executionRefusal = "local VM execution is not implemented or qualified; no fallback is permitted"

// Targets returns proposed build targets, never a supported-release matrix.
func Targets() []Target {
	return []Target{
		proposedTarget("darwin", "arm64", "apple-virtualization-linux-vm"),
		proposedTarget("darwin", "amd64", "apple-virtualization-linux-vm"),
		proposedTarget("linux", "arm64", "linux-kvm-linux-vm"),
		proposedTarget("linux", "amd64", "linux-kvm-linux-vm"),
		proposedTarget("windows", "amd64", "windows-whp-linux-vm"),
	}
}

func proposedTarget(goos, arch, backend string) Target {
	return Target{OS: goos, Arch: arch, ProposedBackend: backend, Qualification: "not-qualified"}
}

func targetFor(goos, arch string) (Target, bool) {
	for _, target := range Targets() {
		if target.OS == goos && target.Arch == arch {
			return target, true
		}
	}
	return proposedTarget(goos, arch, "none"), false
}

// Preflight probes only the current host, with no user-selected paths, helpers,
// environment overrides, network access, VM creation or privilege escalation.
func Preflight() Report {
	target, proposed := targetFor(runtime.GOOS, runtime.GOARCH)
	observations := []Observation{}
	if proposed {
		observations = probeHost()
	}
	return reportFor(target, proposed, observations)
}

func reportFor(target Target, proposed bool, observations []Observation) Report {
	state := prerequisiteState(observations)
	reasons := []string{}
	if !proposed {
		state = Unavailable
		reasons = append(reasons, "target-not-proposed")
	}
	if state != Available {
		reasons = append(reasons, "host-prerequisites-"+string(state))
	}
	reasons = append(reasons, "backend-not-implemented", "backend-not-runtime-tested", "backend-not-qualified")
	return Report{
		Schema:     "testifysec.hardened-opencode.execution-preflight/v1",
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Target:     target, TargetProposed: proposed, Prerequisites: state,
		Observations: observations, ExecutionAllowed: false, RefusalReasons: reasons,
		EvidenceScope: "unsigned-local-api-observation-not-hardware-attestation",
	}
}

func prerequisiteState(observations []Observation) State {
	if len(observations) == 0 {
		return Unknown
	}
	result := Available
	for _, observation := range observations {
		if observation.State == Unavailable {
			return Unavailable
		}
		if observation.State != Available {
			result = Unknown
		}
	}
	return result
}

// RequireExecution is deliberately independent of caller-mutable diagnostic
// reports. No report, positive OS probe, flag or environment variable grants
// execution. Replace this guard only when a real qualified backend is wired in.
func RequireExecution() error { return errExecutionUnavailable }

func booleanObservation(id, method string, value uint32, err error) Observation {
	result := Observation{ID: id, Method: method, State: Unknown, Detail: "query-failed"}
	if err != nil {
		return result
	}
	switch value {
	case 0:
		result.State, result.Detail = Unavailable, "reported-false"
	case 1:
		result.State, result.Detail = Available, "reported-true"
	default:
		result.Detail = "unexpected-boolean-value"
	}
	return result
}
