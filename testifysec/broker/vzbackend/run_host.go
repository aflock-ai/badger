package vzbackend

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

type hostLimits struct{ grace, wait, drain time.Duration }

var realHostLimits = hostLimits{35 * time.Second, 5 * time.Second, 3 * time.Second}

type hostOutput struct {
	bytes         []byte
	eof, overflow bool
	err           error
}
type hostProcess struct {
	invoked, exitObserved, groupAbsent, forced bool
	exitCode                                   *int
	stdout, stderr                             hostOutput
	started, finished                          time.Time
}

func readHostPipe(file *os.File, limit int, cancel context.CancelFunc) <-chan hostOutput {
	done := make(chan hostOutput, 1)
	go func() {
		var output hostOutput
		buffer := make([]byte, 32<<10)
		for {
			n, err := file.Read(buffer)
			if n > 0 {
				remaining := limit - len(output.bytes)
				keep := n
				if keep > remaining {
					keep = remaining
					output.overflow = true
					cancel()
				}
				output.bytes = append(output.bytes, buffer[:keep]...)
			}
			if err != nil {
				output.eof = err == io.EOF
				if !output.eof {
					output.err = err
					cancel()
				}
				break
			}
		}
		done <- output
	}()
	return done
}
func joinHostPipe(file *os.File, done <-chan hostOutput, timeout time.Duration) hostOutput {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case output := <-done:
		_ = file.Close()
		return output
	case <-timer.C:
	}
	closeErr := file.Close()
	timer.Reset(timeout)
	select {
	case output := <-done:
		output.eof = false
		output.err = errors.Join(output.err, closeErr, refused("host_output_incomplete"))
		return output
	case <-timer.C:
		return hostOutput{err: errors.Join(errCleanup, closeErr)}
	}
}
func runHost(ctx context.Context, executable, config, working string, limits hostLimits) (result hostProcess, resultErr error) {
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		return result, err
	}
	defer closeHostFile(outRead, &resultErr)
	defer closeHostFile(outWrite, &resultErr)
	errRead, errWrite, err := os.Pipe()
	if err != nil {
		return result, err
	}
	defer closeHostFile(errRead, &resultErr)
	defer closeHostFile(errWrite, &resultErr)
	active, cancel := context.WithCancel(ctx)
	defer cancel()
	// #nosec G204 -- Run supplies only its privately staged, digest-verified fixed host and internally generated config; no caller executable or argv is accepted.
	command := exec.Command(executable, config)
	command.Dir = working
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + working, "TMPDIR=" + working, "LANG=C"}
	command.Stdin = nil
	command.Stdout = outWrite
	command.Stderr = errWrite
	hostAttributes(command)
	if active.Err() != nil {
		return result, refused("run_cancelled")
	}
	if err = command.Start(); err != nil {
		return result, refused("host_start")
	}
	result.invoked = true
	result.started = time.Now().UTC()
	closeErr := errors.Join(outWrite.Close(), errWrite.Close())
	if closeErr != nil {
		cancel()
	}
	stdout := readHostPipe(outRead, runObservationLimit, cancel)
	stderr := readHostPipe(errRead, 64<<10, cancel)
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	observed, forced, waitErr := waitHost(active, command, wait, limits)
	result.forced = forced
	result.exitObserved = observed
	if observed {
		code := command.ProcessState.ExitCode()
		result.exitCode = &code
	}
	groupErr := finishCommand(command)
	result.groupAbsent = observed && !errors.Is(groupErr, errCleanup)
	result.stdout = joinHostPipe(outRead, stdout, limits.drain)
	result.stderr = joinHostPipe(errRead, stderr, limits.drain)
	result.finished = time.Now().UTC()
	return result, hostResultError(result, waitErr, groupErr, closeErr, active.Err())
}
func unsafeHostProcess(p hostProcess, waitErr error) bool {
	return !p.exitObserved || !p.groupAbsent || p.forced || waitErr != nil || errors.Is(p.stdout.err, errCleanup) || errors.Is(p.stderr.err, errCleanup)
}
func hostResultError(p hostProcess, waitErr, groupErr, closeErr, cancelled error) error {
	if unsafeHostProcess(p, waitErr) {
		return errors.Join(errCleanup, waitErr, groupErr)
	}
	if p.stdout.overflow || p.stderr.overflow {
		return refused("host_output_bounds")
	}
	if !p.stdout.eof || !p.stderr.eof || closeErr != nil {
		return refused("host_output_incomplete")
	}
	if groupErr != nil {
		return refused("host_descendants")
	}
	if cancelled != nil {
		return refused("run_cancelled")
	}
	return nil
}

func waitHost(ctx context.Context, command *exec.Cmd, done <-chan error, limits hostLimits) (observed, forced bool, resultErr error) {
	select {
	case err := <-done:
		return true, false, hostWaitError(err)
	case <-ctx.Done():
	}
	signalErr := signalHost(command, false)
	grace := time.NewTimer(limits.grace)
	defer grace.Stop()
	select {
	case err := <-done:
		return true, false, errors.Join(signalErr, hostWaitError(err))
	case <-grace.C:
	}
	killErr := signalHost(command, true)
	timer := time.NewTimer(limits.wait)
	defer timer.Stop()
	select {
	case err := <-done:
		return true, true, errors.Join(signalErr, killErr, hostWaitError(err))
	case <-timer.C:
		return false, true, errors.Join(errCleanup, signalErr, killErr)
	}
}

func hostWaitError(err error) error {
	var exit *exec.ExitError
	if err == nil || errors.As(err, &exit) {
		return nil
	}
	return err
}

func closeHostFile(file *os.File, resultErr *error) {
	err := file.Close()
	if err != nil && !errors.Is(err, os.ErrClosed) {
		*resultErr = errors.Join(*resultErr, errCleanup, err)
	}
}
