//go:build unix

package launch

import (
	"debug/elf"
	"errors"
	"fmt"
	"runtime"
)

// machines maps the host's architecture to the ELF machine a plugin must be built for.
var machines = map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}

// errNotStatic is wrapped by every refusal of checkStatic.
var errNotStatic = errors.New("plugins must be statically linked executables for this machine: build with CGO_ENABLED=0 and the default build mode, check with readelf -l (no INTERP)")

// checkStatic refuses anything but a self-contained executable: an ELF file for this machine with no
// interpreter (PT_INTERP). Without an interpreter the kernel loads only the file itself (binfmt_elf
// never acts on DT_NEEDED; only an interpreter does), so the signed digest covers all the code the
// kernel loads. A script's interpreter or a dynamic executable's loader and libraries would be files
// no signature covers. A static PIE (ET_DYN without an interpreter) is allowed. Code that loads more
// by itself finds nothing unverified to load: the sandbox hides the vendor's image (hidden).
func checkStatic(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("the plugin executable is not an ELF file (a script or another format); %w", errNotStatic)
	}
	defer f.Close()
	if want, ok := machines[runtime.GOARCH]; !ok || f.Machine != want {
		return fmt.Errorf("the plugin executable is built for %s, not %s; %w", f.Machine, runtime.GOARCH, errNotStatic)
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return fmt.Errorf("the plugin executable is an ELF %s, not an executable; %w", f.Type, errNotStatic)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return fmt.Errorf("the plugin executable has an INTERP program header (dynamically linked); %w", errNotStatic)
		}
	}
	return nil
}
