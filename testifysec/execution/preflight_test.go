// jade:ring local
package execution

import (
	"errors"
	"runtime"
	"testing"
)

func TestPrerequisiteStatesNeverAuthorizeExecution(t *testing.T) {
	for _, item := range []struct {
		name         string
		observations []Observation
		want         State
	}{
		{"all-positive", []Observation{{State: Available}, {State: Available}}, Available},
		{"unknown", []Observation{{State: Available}, {State: Unknown}}, Unknown},
		{"unavailable", []Observation{{State: Available}, {State: Unavailable}}, Unavailable},
		{"unknown-and-unavailable", []Observation{{State: Unknown}, {State: Unavailable}}, Unavailable},
		{"malformed-state", []Observation{{State: "yes"}}, Unknown},
		{"empty", []Observation{}, Unknown},
	} {
		t.Run(item.name, func(t *testing.T) {
			report := reportFor(Targets()[0], true, item.observations)
			if report.Prerequisites != item.want || report.ExecutionAllowed || report.Target.BackendImplemented || report.Target.BackendRuntimeTested || report.Target.Qualification != "not-qualified" {
				t.Fatalf("incorrect capability/execution separation: %+v", report)
			}
			// Public output is mutable diagnostic data, never input authority.
			report.ExecutionAllowed = true
			report.Target.BackendImplemented = true
			report.Target.BackendRuntimeTested = true
			report.Target.Qualification = "qualified"
			if RequireExecution() == nil {
				t.Fatal("diagnostic mutation enabled execution")
			}
		})
	}
}

func TestProposedMatrixIsFixedAndUnqualified(t *testing.T) {
	want := map[string]string{
		"darwin/arm64": "apple-virtualization-linux-vm", "darwin/amd64": "apple-virtualization-linux-vm",
		"linux/arm64": "linux-kvm-linux-vm", "linux/amd64": "linux-kvm-linux-vm",
		"windows/amd64": "windows-whp-linux-vm",
	}
	for _, target := range Targets() {
		key := target.OS + "/" + target.Arch
		if target.ProposedBackend != want[key] || target.BackendImplemented || target.BackendRuntimeTested || target.Qualification != "not-qualified" {
			t.Fatalf("invalid proposed target: %+v", target)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatal("missing proposed targets", want)
	}
	for _, tuple := range [][2]string{{"windows", "arm64"}, {"linux", "386"}, {"freebsd", "amd64"}, {"", ""}} {
		target, ok := targetFor(tuple[0], tuple[1])
		if ok || target.ProposedBackend != "none" {
			t.Fatalf("unsupported target accepted: %+v", target)
		}
		report := reportFor(target, ok, []Observation{{State: Available}})
		if report.ExecutionAllowed || report.Prerequisites != Unavailable || report.RefusalReasons[0] != "target-not-proposed" {
			t.Fatalf("unsupported target did not refuse: %+v", report)
		}
	}
	changed := Targets()
	changed[0].Qualification = "qualified"
	if Targets()[0].Qualification != "not-qualified" {
		t.Fatal("caller mutated the compiled target matrix")
	}
}

func TestBooleanProbeRefusesUnknownValues(t *testing.T) {
	for _, item := range []struct {
		value uint32
		err   error
		want  State
	}{
		{0, nil, Unavailable}, {1, nil, Available}, {2, nil, Unknown},
		{0xffffffff, nil, Unknown}, {1, errors.New("sensitive-os-error"), Unknown},
	} {
		got := booleanObservation("probe", "native", item.value, item.err)
		if got.State != item.want || got.Detail == "sensitive-os-error" {
			t.Fatalf("incorrect boolean probe: %+v", got)
		}
	}
}

func TestCurrentHostNativeProbeRemainsDiagnostic(t *testing.T) {
	report := Preflight()
	if report.Target.OS != runtime.GOOS || report.Target.Arch != runtime.GOARCH || report.ExecutionAllowed || RequireExecution() == nil {
		t.Fatalf("invalid host report: %+v", report)
	}
	if report.TargetProposed && len(report.Observations) == 0 {
		t.Fatal("proposed current target has no actual probe")
	}
	for _, observation := range report.Observations {
		if observation.ID == "" || observation.Method == "" || observation.Detail == "" {
			t.Fatalf("missing observation provenance: %+v", observation)
		}
		if observation.State != Available && observation.State != Unavailable && observation.State != Unknown {
			t.Fatalf("invalid state: %+v", observation)
		}
	}
	t.Logf("real current-host observation (not VM execution UAT): %+v", report)
}
