package vzbackend

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func stream(ctx context.Context, dst io.Writer, src io.Reader, limit int64) (File, error) {
	h := sha256.New()
	writer := io.MultiWriter(dst, h)
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if ctx.Err() != nil {
			return File{}, refused("cancelled")
		}
		n, err := src.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > limit {
				return File{}, refused("file_bounds")
			}
			if _, e := writer.Write(buffer[:n]); e != nil {
				return File{}, e
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return File{}, err
		}
		if n == 0 {
			return File{}, io.ErrNoProgress
		}
	}
	if ctx.Err() != nil {
		return File{}, refused("cancelled")
	}
	return File{hex.EncodeToString(h.Sum(nil)), total}, nil
}
func readBounded(ctx context.Context, root *os.Root, name string, limit int64) (raw []byte, resultErr error) {
	f, before, err := openChecked(root, name, false)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	if before.Size() < 1 || before.Size() > limit {
		return nil, refused("file_bounds")
	}
	raw = make([]byte, before.Size())
	if ctx.Err() != nil {
		return nil, refused("cancelled")
	}
	if _, err = io.ReadFull(f, raw); err != nil {
		return nil, err
	}
	var extra [1]byte
	n, e := f.Read(extra[:])
	if n != 0 || e != io.EOF {
		return nil, refused("file_changed")
	}
	if err = checkFile(root, name, f, before); err != nil {
		return nil, err
	}
	return raw, nil
}
func checkMachO(file *os.File) error {
	// Read only the fixed 64-bit Mach-O header. This is target classification of
	// approved bytes, not full object validation, code-signing or qualification.
	var header [32]byte
	if _, err := file.ReadAt(header[:], 0); err != nil {
		return refused("host_format")
	}
	if binary.LittleEndian.Uint32(header[0:4]) != 0xfeedfacf {
		return refused("host_format")
	}
	if binary.LittleEndian.Uint32(header[4:8]) != 0x0100000c || binary.LittleEndian.Uint32(header[12:16]) != 2 {
		return refused("host_target")
	}
	return nil
}

func verifyRole(ctx context.Context, root *os.Root, r role) (resultErr error) {
	f, before, err := openChecked(root, r.name, r.executable)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	if before.Size() != r.file.Size {
		return refused("file_size")
	}
	if r.executable {
		if err = checkMachO(f); err != nil {
			return err
		}
	}
	observed, err := stream(ctx, io.Discard, f, r.limit)
	if err != nil {
		return err
	}
	if observed != r.file {
		return refused("file_digest")
	}
	return checkFile(root, r.name, f, before)
}
func copyRole(ctx context.Context, source, destination *os.Root, r role) (resultErr error) {
	input, before, err := openChecked(source, r.name, r.executable)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, input.Close()) }()
	if before.Size() != r.file.Size {
		return refused("file_size")
	}
	if r.executable {
		if err = checkMachO(input); err != nil {
			return err
		}
	}
	output, err := destination.OpenFile(r.name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, output.Close()) }()
	observed, err := stream(ctx, output, input, r.limit)
	if err != nil {
		return err
	}
	if observed != r.file {
		return refused("file_digest")
	}
	if err = checkFile(source, r.name, input, before); err != nil {
		return err
	}
	mode := os.FileMode(0400)
	if r.executable {
		mode = 0500
	}
	return output.Chmod(mode)
}

// LoadAssignment reads one protected administrator-owned regular file. This
// helper grants no authority to caller-controlled workspace configuration.
func LoadAssignment(path string) (Assignment, error) {
	var a Assignment
	if !absolute(path) {
		return a, refused("assignment_invalid")
	}
	c, err := openCustody(filepath.Dir(path), false)
	if err != nil {
		return a, err
	}
	raw, err := readBounded(context.Background(), c.root(), filepath.Base(path), 16<<10)
	if err == nil {
		err = c.check()
	}
	err = errors.Join(err, c.close())
	if err != nil {
		return a, err
	}
	if strict(raw, &a) != nil {
		return a, refused("assignment_invalid")
	}
	return a, validateAssignment(a)
}
