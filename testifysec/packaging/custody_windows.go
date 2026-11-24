package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// Keep every directory handle open without delete sharing until cleanup. Check
// custody before creation: a child's DACL cannot defeat parent DELETE_CHILD.
func windowsParent(profile, sid string) (*os.Root, func() error, error) {
	var held []*os.Root
	release := func() error {
		var err error
		for i := len(held) - 1; i >= 0; i-- {
			err = errors.Join(err, held[i].Close())
		}
		return err
	}
	volume := filepath.VolumeName(profile)
	current := volume + `\`
	paths := []string{current}
	for _, part := range strings.Split(strings.TrimPrefix(profile[len(volume):], `\`), `\`) {
		if part == "" || part == "." || part == ".." {
			release()
			return nil, nil, errors.New("invalid profile path")
		}
		current = filepath.Join(current, part)
		paths = append(paths, current)
	}
	for _, name := range paths {
		wide, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			release()
			return nil, nil, err
		}
		attributes, err := syscall.GetFileAttributes(wide)
		if err != nil || attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			release()
			return nil, nil, errors.New("profile ancestor reparse point")
		}
		before, err := os.Lstat(name)
		if err != nil || !before.IsDir() {
			release()
			return nil, nil, errors.New("profile ancestor type")
		}
		root, err := os.OpenRoot(name)
		if err != nil {
			release()
			return nil, nil, err
		}
		held = append(held, root)
		after, err := root.Stat(".")
		if err != nil || !os.SameFile(before, after) {
			release()
			return nil, nil, errors.New("profile ancestor changed")
		}
		if err = windowsCustody(root, sid); err != nil {
			release()
			return nil, nil, err
		}
	}
	return held[len(held)-1], release, nil
}

func windowsCustody(root *os.Root, user string) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	var owner *syscall.SID
	var acl, descriptor uintptr
	status, _, _ := security.NewProc("GetSecurityInfo").Call(file.Fd(), 1, 1|4, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&acl)), 0, uintptr(unsafe.Pointer(&descriptor)))
	if status != 0 || descriptor == 0 || owner == nil || acl == 0 {
		return errors.New("directory owner and DACL required")
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	trusted := func(sid string) bool {
		return sid == user || sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	}
	ownerText, err := owner.String()
	if err != nil || !trusted(ownerText) {
		return errors.New("untrusted directory owner")
	}
	var info struct{ Count, InUse, Free uint32 }
	ok, _, _ := security.NewProc("GetAclInformation").Call(acl, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 2)
	if ok == 0 || info.Count > 1024 {
		return errors.New("directory DACL bounds")
	}
	for i := uint32(0); i < info.Count; i++ {
		var pointer uintptr
		ok, _, _ = security.NewProc("GetAce").Call(acl, uintptr(i), uintptr(unsafe.Pointer(&pointer)))
		if ok == 0 || pointer == 0 {
			return errors.New("directory ACE unavailable")
		}
		ace := (*struct {
			Type, Flags uint8
			Size        uint16
			Mask        uint32
		})(unsafe.Pointer(pointer))
		if ace.Flags&8 != 0 || ace.Type == 1 {
			continue
		} // inherit-only or deny: no access granted here
		if ace.Type != 0 || ace.Size < 16 {
			return errors.New("unsupported directory allow ACE")
		}
		// Adding siblings is harmless; alteration, deletion or DACL/owner changes
		// by other principals could substitute an executable's pathname.
		if ace.Mask&(0x50000000|0x000d0150) == 0 {
			continue
		}
		sid := (*syscall.SID)(unsafe.Pointer(pointer + 8))
		valid, _, _ := security.NewProc("IsValidSid").Call(uintptr(unsafe.Pointer(sid)))
		length, _, _ := security.NewProc("GetLengthSid").Call(uintptr(unsafe.Pointer(sid)))
		if valid == 0 || length+8 > uintptr(ace.Size) {
			return errors.New("directory ACE SID bounds")
		}
		text, err := sid.String()
		if err != nil || !trusted(text) {
			return errors.New("directory writable by another principal")
		}
	}
	return nil
}
