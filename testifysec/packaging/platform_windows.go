package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var security = syscall.NewLazyDLL("advapi32.dll")

func privateDirectory() (*os.Root, string, func(bool) error, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return nil, "", nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, "", nil, err
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return nil, "", nil, err
	}
	profile, err := token.GetUserProfileDirectory()
	if err != nil || !filepath.IsAbs(profile) || strings.HasPrefix(profile, `\\`) {
		return nil, "", nil, errors.New("local Windows profile required")
	}
	profileUTF16, err := syscall.UTF16PtrFromString(profile)
	if err != nil {
		return nil, "", nil, err
	}
	attributes, err := syscall.GetFileAttributes(profileUTF16)
	if err != nil || attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, "", nil, errors.New("profile reparse point refused")
	}
	volume := make([]uint16, 32768)
	ok, _, _ := kernel.NewProc("GetVolumePathNameW").Call(uintptr(unsafe.Pointer(profileUTF16)), uintptr(unsafe.Pointer(&volume[0])), uintptr(len(volume)))
	if ok == 0 {
		return nil, "", nil, errors.New("profile volume unavailable")
	}
	var flags uint32
	ok, _, _ = kernel.NewProc("GetVolumeInformationW").Call(uintptr(unsafe.Pointer(&volume[0])), 0, 0, 0, 0, uintptr(unsafe.Pointer(&flags)), 0, 0)
	if ok == 0 || flags&8 == 0 {
		return nil, "", nil, errors.New("persistent Windows ACLs required")
	}
	parent, release, err := windowsParent(profile, sid)
	if err != nil {
		return nil, "", nil, err
	}
	// Protected DACL is applied at creation, never after writing payload bytes.
	// Only this exact token user and SYSTEM inherit access to descendants.
	sddl, err := syscall.UTF16PtrFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)")
	if err != nil {
		release()
		return nil, "", nil, err
	}
	var descriptor uintptr
	ok, _, _ = security.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW").Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 || descriptor == 0 {
		release()
		return nil, "", nil, errors.New("private Windows DACL unavailable")
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		release()
		return nil, "", nil, err
	}
	name := "hardened-code-" + hex.EncodeToString(nonce[:])
	directory := filepath.Join(profile, name)
	wide, err := syscall.UTF16PtrFromString(directory)
	if err != nil {
		release()
		return nil, "", nil, err
	}
	attributesSA := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: descriptor}
	if err = syscall.CreateDirectory(wide, &attributesSA); err != nil {
		release()
		return nil, "", nil, err
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		parent.RemoveAll(name)
		release()
		return nil, "", nil, err
	}
	clean := func(remove bool) error {
		if !remove {
			return errors.Join(root.Close(), release())
		}
		// Windows read-only attributes must be cleared before deletion. Root
		// operations stay confined; WalkDir does not descend through symlinks.
		err := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, prior error) error {
			if prior != nil {
				return prior
			}
			if entry.Type().IsRegular() {
				return root.Chmod(name, 0600)
			}
			return nil
		})
		return errors.Join(err, root.Close(), parent.RemoveAll(name), release())
	}
	return root, directory, clean, nil
}

func childEnvironment(scratch string) ([]string, error) {
	buffer := make([]uint16, 32768)
	n, _, _ := kernel.NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if n == 0 || n >= uintptr(len(buffer)) {
		return nil, errors.New("Windows system directory unavailable")
	}
	system := syscall.UTF16ToString(buffer)
	return []string{"PATH=" + system, "SystemRoot=" + filepath.Dir(system), "WINDIR=" + filepath.Dir(system), "LANG=C", "TEMP=" + scratch, "TMP=" + scratch, "USERPROFILE=" + scratch}, nil
}

type jobLimits struct {
	ProcessTime, JobTime                                       int64
	Flags                                                      uint32
	MinWorkingSet, MaxWorkingSet                               uintptr
	ActiveProcesses                                            uint32
	Affinity                                                   uintptr
	Priority, Scheduling                                       uint32
	IOCounters                                                 [6]uint64
	ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory uintptr
}

// Create the fixed entry suspended, assign it before any user code runs, then
// resume it. This closes the fast-helper race in post-Start job assignment.
func supervise(command *exec.Cmd) (int, bool, error) {
	job, _, _ := kernel.NewProc("CreateJobObjectW").Call(0, 0)
	if job == 0 {
		return 2, true, errors.New("Windows supervision unavailable")
	}
	defer syscall.CloseHandle(syscall.Handle(job))
	limits := jobLimits{Flags: 0x2000}
	ok, _, _ := kernel.NewProc("SetInformationJobObject").Call(job, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if ok == 0 {
		return 2, true, errors.New("Windows job limits unavailable")
	}
	application, err := syscall.UTF16PtrFromString(command.Path)
	if err != nil {
		return 2, true, err
	}
	arguments, err := syscall.UTF16PtrFromString(syscall.EscapeArg(command.Path))
	if err != nil {
		return 2, true, err
	}
	directory, err := syscall.UTF16PtrFromString(command.Dir)
	if err != nil {
		return 2, true, err
	}
	environment := append([]string{}, command.Env...)
	sort.Slice(environment, func(i, j int) bool { return strings.ToUpper(environment[i]) < strings.ToUpper(environment[j]) })
	var block []uint16
	for _, value := range environment {
		encoded, err := syscall.UTF16FromString(value)
		if err != nil {
			return 2, true, err
		}
		block = append(block, encoded...)
	}
	block = append(block, 0)
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return 2, true, err
	}
	var handles [3]syscall.Handle
	for index, source := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		if err = syscall.DuplicateHandle(current, syscall.Handle(source.Fd()), current, &handles[index], 0, true, syscall.DUPLICATE_SAME_ACCESS); err != nil {
			return 2, true, err
		}
		defer syscall.CloseHandle(handles[index])
	}
	startup := syscall.StartupInfo{Cb: uint32(unsafe.Sizeof(syscall.StartupInfo{})), Flags: syscall.STARTF_USESTDHANDLES, StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2]}
	var process syscall.ProcessInformation
	if err = syscall.CreateProcess(application, arguments, nil, nil, true, 0x00000004|0x00000400, &block[0], directory, &startup, &process); err != nil {
		return 2, true, err
	}
	defer syscall.CloseHandle(process.Process)
	defer syscall.CloseHandle(process.Thread)
	ok, _, _ = kernel.NewProc("AssignProcessToJobObject").Call(job, uintptr(process.Process))
	if ok == 0 {
		stopErr := syscall.TerminateProcess(process.Process, 2)
		result, waitErr := syscall.WaitForSingleObject(process.Process, 5000)
		stopped := waitErr == nil && result == syscall.WAIT_OBJECT_0
		if !stopped {
			waitErr = errors.Join(waitErr, errors.New("Windows unassigned entry did not stop"))
		}
		return 2, stopped, errors.Join(errors.New("Windows job assignment refused"), stopErr, waitErr)
	}
	resumed, _, _ := kernel.NewProc("ResumeThread").Call(uintptr(process.Thread))
	if resumed == 0xffffffff {
		return finishWindowsJob(job, 2, errors.New("Windows entrypoint resume failed"))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	for {
		result, err := syscall.WaitForSingleObject(process.Process, 100)
		if err != nil {
			return finishWindowsJob(job, 2, err)
		}
		if result == syscall.WAIT_OBJECT_0 {
			break
		}
		if result != uint32(syscall.WAIT_TIMEOUT) {
			return finishWindowsJob(job, 2, errors.New("Windows wait failed"))
		}
		if ctx.Err() != nil {
			return finishWindowsJob(job, 130, nil)
		}
	}
	var code uint32
	if err = syscall.GetExitCodeProcess(process.Process, &code); err != nil {
		return finishWindowsJob(job, 2, err)
	}
	return finishWindowsJob(job, int(code), nil)
}

func finishWindowsJob(job uintptr, code int, failure error) (int, bool, error) {
	if err := stopWindowsJob(job, uint32(code)); err != nil {
		return 2, false, errors.Join(failure, err)
	}
	return code, true, failure
}

func stopWindowsJob(job uintptr, code uint32) error {
	ok, _, _ := kernel.NewProc("TerminateJobObject").Call(job, uintptr(code))
	if ok == 0 {
		return errors.New("Windows job termination failed")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var accounting struct {
			User, Kernel, PeriodUser, PeriodKernel int64
			Faults, Total, Active, Terminated      uint32
		}
		ok, _, _ = kernel.NewProc("QueryInformationJobObject").Call(job, 1, uintptr(unsafe.Pointer(&accounting)), unsafe.Sizeof(accounting), 0)
		if ok == 0 {
			return errors.New("Windows job drain unavailable")
		}
		if accounting.Active == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.New("Windows job drain timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
