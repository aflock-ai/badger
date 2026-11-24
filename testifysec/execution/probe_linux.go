package execution

import (
	"errors"
	"syscall"
)

func probeHost() []Observation {
	observation := Observation{ID: "kvm-device-api", State: Unknown,
		Method: "open(/dev/kvm,O_RDWR|O_CLOEXEC|O_NOFOLLOW);fstat;ioctl(KVM_GET_API_VERSION)", Detail: "query-failed"}
	fd, err := syscall.Open("/dev/kvm", syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENODEV) {
			observation.State = Unavailable
			observation.Detail = "device-absent-or-inaccessible-to-current-process"
		}
		return []Observation{observation}
	}
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err == nil && stat.Mode&syscall.S_IFMT == syscall.S_IFCHR {
		// KVM_GET_API_VERSION = _IO(KVMIO, 0x00), stable ABI version 12.
		version, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0xae00, 0)
		if errno == 0 && version == 12 {
			observation.State, observation.Detail = Available, "accessible-character-device-reported-api-12;no-vm-created"
		} else if errno == 0 {
			observation.State, observation.Detail = Unavailable, "unexpected-kvm-api-version"
		}
	} else if err == nil {
		observation.State, observation.Detail = Unavailable, "not-a-character-device"
	}
	if syscall.Close(fd) != nil {
		observation.State, observation.Detail = Unknown, "device-close-failed"
	}
	return []Observation{observation}
}
