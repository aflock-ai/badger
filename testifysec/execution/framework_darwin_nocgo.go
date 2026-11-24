//go:build darwin && !cgo

package execution

func probeAppleFramework() []Observation {
	return []Observation{
		{ID: "virtualization-framework-support", State: Unknown, Method: "not-called", Detail: "native-framework-bridge-not-built"},
		{ID: "current-task-virtualization-entitlement", State: Unknown, Method: "not-called", Detail: "native-framework-bridge-not-built"},
	}
}
