//go:build !darwin && !linux && !windows

package execution

func probeHost() []Observation { return []Observation{} }
