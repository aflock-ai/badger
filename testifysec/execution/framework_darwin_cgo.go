//go:build darwin && cgo

package execution

/*
#cgo LDFLAGS: -framework Foundation -framework Virtualization -framework Security
int hc_vz_supported(void);
int hc_vz_entitlement(void);
*/
import "C"

func probeAppleFramework() []Observation {
	return []Observation{
		appleObservation("virtualization-framework-support", "VZVirtualMachine.isSupported", int(C.hc_vz_supported())),
		appleObservation("current-task-virtualization-entitlement", "SecTaskCreateFromSelf;SecTaskCopyValueForEntitlement(com.apple.security.virtualization)", int(C.hc_vz_entitlement())),
	}
}

func appleObservation(id, method string, value int) Observation {
	if value < 0 {
		return Observation{ID: id, Method: method, State: Unknown, Detail: "native-api-error-or-unrecognized-entitlement-type"}
	}
	return booleanObservation(id, method, uint32(value), nil)
}
