package vzbackend

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"time"
)

// Run consumes this prepared backend once. It constructs every VM input from
// typed, bounded service inputs and its own admitted assignment. It never
// deletes the backend; the service stops its gateway, then Close or Retain.
func (p *Prepared) Run(ctx context.Context, request RunRequest) (result RunResult, resultErr error) {
	result.Schema = "testifysec.aflock.vz-run/v1"
	if err := p.beginRun(); err != nil {
		return result, err
	}
	result.CleanupSafe = true
	defer func() {
		if errors.Is(resultErr, errCleanup) {
			result.CleanupSafe = false
		}
		p.mu.Lock()
		p.runUnsafe = p.runUnsafe || !result.CleanupSafe || errors.Is(resultErr, errCleanup)
		p.mu.Unlock()
		close(p.runDone)
	}()
	active, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return result, refused("run_unsupported_platform")
	}
	expected, err := p.buildRunJob(request)
	if err != nil {
		return result, err
	}
	fillRunInputs(&result, p, request, expected)
	if err = p.createRunFiles(active, request, expected); err != nil {
		return result, err
	}
	result.ConfigSHA256 = p.runConfigSHA256
	if err = p.beforeRun(active, request); err != nil {
		return result, err
	}
	lifetime, stopLifetime := context.WithTimeout(active, time.Duration(request.TimeoutSeconds+35)*time.Second)
	defer stopLifetime()
	process, processErr := runHost(lifetime, filepath.Join(p.path, "hc-vm"), filepath.Join(p.runStage.path, "config.json"), p.runStage.path, realHostLimits)
	resultErr = p.completeRun(&result, expected, process, processErr)
	return result, resultErr
}

func (p *Prepared) completeRun(result *RunResult, expected runExpected, process hostProcess, processErr error) error {
	fillRunProcess(result, process)
	if !process.invoked {
		return processErr
	}
	result.CleanupSafe = false
	if process.stdout.eof && !process.stdout.overflow {
		result.ObservationJSON = append([]byte(nil), process.stdout.bytes...)
		result.ObservationSHA256 = hash(result.ObservationJSON)
	}
	lifecycle, validationErr := validateRunObservation(result.ObservationJSON, expected)
	if errors.Is(processErr, errCleanup) {
		return errors.Join(processErr, validationErr)
	}
	if !process.exitObserved || process.exitCode == nil || !process.stdout.eof || !process.stderr.eof || !process.groupAbsent {
		return errors.Join(errCleanup, processErr, validationErr)
	}
	if !hostExitMatches(*process.exitCode, lifecycle.Completed) {
		return errors.Join(refused("host_exit_conflict"), validationErr)
	}
	result.CleanupSafe = lifecycle.CleanupSafe
	if lifecycle.CleanupSafe {
		if err := p.verifyAfterRun(); err != nil {
			result.CleanupSafe = false
			return errors.Join(errCleanup, err, processErr, validationErr)
		}
	}
	result.Completed = lifecycle.Completed && processErr == nil && validationErr == nil
	return errors.Join(processErr, validationErr)
}
func (p *Prepared) beginRun() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(); err != nil {
		return err
	}
	if p.runDone != nil {
		return refused("run_consumed")
	}
	p.runDone = make(chan struct{})
	return nil
}
func (p *Prepared) beforeRun(ctx context.Context, request RunRequest) error {
	verifier, err := New(p.assignment)
	if err != nil {
		return err
	}
	admitted, err := verifier.admit(ctx, p.envelope, p.runStage.path)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.notBefore, p.expires = admitted.notBefore, admitted.expires
	if _, err = p.inspectLocked(ctx); err != nil {
		return err
	}
	if err = p.verifyRunFiles(ctx); err != nil {
		return err
	}
	if err = p.check(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return refused("run_cancelled")
	}
	if !time.Now().Before(request.NotAfter) {
		return refused("run_not_after")
	}
	return nil
}
func hostExitMatches(code int, completed bool) bool {
	return (completed && code == 0) || (!completed && code == 3)
}
func fillRunInputs(result *RunResult, p *Prepared, request RunRequest, expected runExpected) {
	result.JobJSON = append([]byte(nil), expected.JobJSON...)
	result.JobSHA256 = expected.JobSHA256
	result.Binding = expected.Binding
	result.ProfileSHA256 = p.observation.ProfileSHA256
	result.BackendManifestSHA256 = p.observation.ManifestSHA256
	result.GatewayConfigSHA256 = request.GatewayConfigSHA256
	result.InitialManifestSHA256 = expected.InitialManifestSHA256
}
func fillRunProcess(result *RunResult, process hostProcess) {
	result.HostInvoked = process.invoked
	result.HostExitObserved = process.exitObserved
	result.HostExitCode = process.exitCode
	result.HostStdoutEOF = process.stdout.eof
	result.HostStderrEOF = process.stderr.eof
	result.HostGroupAbsent = process.groupAbsent
	result.StartedAt = process.started
	result.FinishedAt = process.finished
}

func (p *Prepared) verifyAfterRun() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.verifyBackend(ctx); err != nil {
		return err
	}
	return p.verifyRunFiles(ctx)
}
