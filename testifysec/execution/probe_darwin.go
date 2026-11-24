package execution

import "syscall"

func probeHost() []Observation {
	value, err := syscall.SysctlUint32("kern.hv_support")
	result := []Observation{booleanObservation("hypervisor-hardware-support", "sysctl(kern.hv_support)", value, err)}
	return append(result, probeAppleFramework()...)
}
