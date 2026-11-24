package execution

import (
	"syscall"
	"unsafe"
)

func probeHost() []Observation {
	observation := Observation{ID: "whp-hypervisor-present", State: Unknown,
		Method: "LoadLibraryExW(WinHvPlatform.dll,LOAD_LIBRARY_SEARCH_SYSTEM32);WHvGetCapability(HypervisorPresent)", Detail: "system-api-query-failed"}
	// kernel32.dll is a Windows KnownDLL used by the Go runtime. Resolve WHP
	// with the OS loader's System32-only search, including its dependencies;
	// never load a candidate from cwd, PATH, or a caller-selected DLL path.
	kernel, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return []Observation{observation}
	}
	defer kernel.Release()
	loader, err := kernel.FindProc("LoadLibraryExW")
	if err != nil {
		return []Observation{observation}
	}
	name, _ := syscall.UTF16PtrFromString("WinHvPlatform.dll")
	handle, _, loadErr := loader.Call(uintptr(unsafe.Pointer(name)), 0, 0x00000800)
	if handle == 0 {
		if loadErr == syscall.Errno(126) { // ERROR_MOD_NOT_FOUND
			observation.State, observation.Detail = Unavailable, "whp-system-library-or-dependency-not-installed"
		}
		return []Observation{observation}
	}
	proc, err := syscall.GetProcAddress(syscall.Handle(handle), "WHvGetCapability")
	if err == nil {
		var value uint64
		var written uint32
		hresult, _, _ := syscall.SyscallN(proc, 0, uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value), uintptr(unsafe.Pointer(&written)))
		// The queried union member is a Windows BOOL (4 bytes), not the
		// 8-byte buffer capacity. Unknown wire/ABI results stay unknown.
		if hresult == 0 && written == 4 && value <= 0xffffffff {
			if value == 0 {
				observation.State, observation.Detail = Unavailable, "windows-hypervisor-not-present"
			} else {
				observation.State, observation.Detail = Available, "hypervisor-present;no-partition-created"
			}
		} else {
			observation.Detail = "capability-call-failed-or-unexpected-result-size"
		}
	}
	if syscall.FreeLibrary(syscall.Handle(handle)) != nil {
		observation.State, observation.Detail = Unknown, "system-library-release-failed"
	}
	return []Observation{observation}
}
