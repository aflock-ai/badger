package vzsession

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/aflock-ai/badger/testifysec/broker/vzbackend"
	"github.com/aflock-ai/badger/testifysec/platform"
)

type Result struct {
	CompletionSemantics      string                    `json:"completionSemantics"`
	Schema                   string                    `json:"schema"`
	Completed                bool                      `json:"completed"`
	Code                     string                    `json:"code"`
	SessionID                string                    `json:"sessionId"`
	CallerRequestSHA256      string                    `json:"callerRequestSha256"`
	AssignmentSHA256         string                    `json:"assignmentSha256"`
	PlatformConfigSHA256     string                    `json:"platformConfigSha256"`
	GatewayTemplateSHA256    string                    `json:"gatewayTemplateSha256"`
	PlatformIdentity         *platformsession.Identity `json:"platformIdentity"`
	AuthorizationSource      string                    `json:"authorizationSource"`
	Execution                vzbackend.RunResult       `json:"execution"`
	GatewayStopped           bool                      `json:"gatewayStopped"`
	StateCleaned             bool                      `json:"stateCleaned"`
	BackendCleaned           bool                      `json:"backendCleaned"`
	AuditRetained            bool                      `json:"auditRetained"`
	Qualification            string                    `json:"qualification"`
	FinalizedSigningEvidence bool                      `json:"finalizedSigningEvidence"`
	SignedOut                bool                      `json:"signedOut"`
}

type session struct {
	config   configuration
	prepared *vzbackend.Prepared
	state    *ownedDirectory
	audit    *ownedDirectory
	spool    *ownedDirectory
	gateway  *child
	identity *platformsession.Client
	// device is the session's broker token (device sign-in); tokenPipe keeps the gateway's copy
	// alive until the session ends. Neither is ever written anywhere.
	device    *deviceToken
	tokenPipe *os.File
}

// browserOpener shows the device approval page; tests replace it.
var browserOpener = openBrowser

// Execute consumes only a prompt, an assigned workspace selector and a bounded
// timeout. All execution authority comes from administrator policy plus native
// signed-profile admission. A fresh platform answer authenticates the principal
// but explicitly grants no operation authority by itself.
func Execute(ctx context.Context, assignmentRaw, requestRaw []byte) (Result, error) {
	return execute(ctx, assignmentRaw, requestRaw, 0)
}

// execute runs one session. The person's sign-in comes first and has its own deadline
// (signInDeadline); sessionLimit, when positive, bounds everything after it, so time spent
// approving in the browser never eats into the session.
func execute(ctx context.Context, assignmentRaw, requestRaw []byte, sessionLimit time.Duration) (result Result, resultErr error) {
	result = Result{Schema: ResultSchema, Qualification: "developer-only-unqualified", AuthorizationSource: "administrator-policy-and-signed-profile", CompletionSemantics: "worker-exit-and-complete-capture"}
	defer func() {
		if resultErr != nil {
			result.Completed = false
			result.Code = Code(resultErr)
		}
	}()
	if !supported() {
		return result, refused("unsupported_platform")
	}
	c, err := configurationFrom(assignmentRaw)
	if err != nil {
		return result, err
	}
	r, err := requestFrom(requestRaw, c.assignment)
	if err != nil {
		return result, err
	}
	result.CallerRequestSHA256 = hash(requestRaw)
	result.AssignmentSHA256 = c.assignmentSHA256
	result.PlatformConfigSHA256 = c.assignment.PlatformConfigSHA256
	result.GatewayTemplateSHA256 = c.assignment.GatewayTemplateSHA256
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return result, err
	}
	result.SessionID = "af-" + hex.EncodeToString(random[:])
	s := &session{config: c}
	defer func() { resultErr = errors.Join(resultErr, s.finish(&result)) }()
	var cancel context.CancelFunc
	s.device, ctx, cancel, err = signInThenLimit(ctx, c.template.BrokerSignIn, browserOpener, sessionLimit)
	if err != nil {
		return result, err
	}
	defer cancel()
	materials, err := snapshot(ctx, c.assignment.WorkspaceDirectory)
	if err != nil {
		return result, err
	}
	if err = s.prepare(ctx, result.SessionID, &result); err != nil {
		return result, err
	}
	if err = s.start(ctx, result.SessionID); err != nil {
		return result, err
	}
	// Re-read immutable configuration inputs before the final online check. The
	// original profile bytes remain inside Prepared for its new native admission.
	current, err := configurationFrom(assignmentRaw)
	if err != nil {
		return result, err
	}
	if hash(current.profile) != hash(c.profile) {
		return result, refused("profile_changed")
	}
	identity, err := s.identity.Check(ctx)
	if err != nil {
		return result, refused("platform_identity")
	}
	result.PlatformIdentity = &identity
	if err = s.state.verify(); err != nil {
		return result, err
	}
	result.Execution, err = s.prepared.Run(ctx, vzbackend.RunRequest{
		SessionID: result.SessionID, Prompt: r.Prompt, TimeoutSeconds: r.TimeoutSeconds, Materials: materials,
		GatewayConfigFile: filepath.Join(s.state.path, "gateway.json"), GatewayConfigSHA256: s.state.files["gateway.json"],
		NotAfter: identity.ExpiresAt,
	})
	if err != nil {
		return result, err
	}
	if !result.Execution.Completed {
		return result, refused("execution_incomplete")
	}
	result.Completed = true
	return result, nil
}

func (s *session) prepare(ctx context.Context, id string, result *Result) error {
	v, err := vzbackend.New(s.config.backend)
	if err != nil {
		return refused("backend_assignment")
	}
	s.prepared, err = v.Prepare(ctx, s.config.profile)
	if err != nil {
		return refused("backend_" + vzbackend.Code(err))
	}
	s.state, err = newDirectory(s.config.assignment.StateDirectory, id)
	if err != nil {
		return err
	}
	if len(filepath.Join(s.state.path, "gateway.sock")) > 103 {
		return refused("socket_path_length")
	}
	s.audit, err = newDirectory(s.config.assignment.AuditDirectory, id)
	if err != nil {
		return err
	}
	result.AuditRetained = true
	s.spool, err = newDirectory(s.audit.path, "spool")
	if err != nil {
		return err
	}
	raw, err := gatewayBytes(s.config.assignment.GatewayExecutable)
	if err != nil || hash(raw) != s.config.assignment.GatewaySHA256 {
		return refused("gateway_digest")
	}
	if err = s.state.write("gateway", raw, 0700); err != nil {
		return err
	}
	if err = s.state.write("profile.dsse.json", s.config.profile, 0400); err != nil {
		return err
	}
	s.identity, err = platformsession.New(s.config.platform)
	if err != nil {
		return refused("platform_configuration")
	}
	return nil
}

func (s *session) start(ctx context.Context, id string) error {
	identity, err := s.identity.Check(ctx)
	if err != nil {
		return refused("platform_identity")
	}
	raw, err := s.config.gatewayConfig(id, s.state.path, s.audit.path, identity)
	if err != nil {
		return err
	}
	if err = s.state.write("gateway.json", raw, 0400); err != nil {
		return err
	}
	r, w, err := s.device.pipe()
	if err != nil {
		return err
	}
	s.tokenPipe = w
	s.gateway, err = startGateway(ctx, s.state, r)
	r.Close()
	if err != nil {
		return refused("gateway_start")
	}
	return s.gateway.ready(ctx, s.state)
}

func (s *session) finish(result *Result) error {
	if s.identity != nil {
		s.identity.Close()
	}
	safe := !result.Execution.HostInvoked || result.Execution.CleanupSafe
	var finishErr error
	if s.gateway != nil {
		result.GatewayStopped = s.gateway.stop()
		if !result.GatewayStopped {
			safe = false
			finishErr = errors.Join(finishErr, errCleanup)
		}
	}
	if s.tokenPipe != nil {
		s.tokenPipe.Close()
	}
	if s.device != nil {
		// The token is useless once this process exits, but valid at the broker until it expires:
		// sign it out. A failure is reported, not hidden; the token still expires on its own.
		result.SignedOut = s.device.signOut(context.Background()) == nil
	}
	if err := s.checkCustody(); err != nil {
		safe = false
		finishErr = errors.Join(finishErr, errCleanup, err)
	}
	if s.prepared != nil {
		err := s.closeBackend(safe, result)
		finishErr = errors.Join(finishErr, err)
		safe = safe && err == nil
	}
	if s.state != nil {
		if safe {
			err := s.state.remove()
			result.StateCleaned = err == nil
			finishErr = errors.Join(finishErr, err)
		}
		finishErr = errors.Join(finishErr, s.state.close())
	}
	if s.audit != nil {
		// Audits survive success, cancellation and failed cleanup. They are never
		// removed with execution scratch and are not themselves signed evidence.
		finishErr = errors.Join(finishErr, s.audit.close())
	}
	if s.spool != nil {
		finishErr = errors.Join(finishErr, s.spool.close())
	}
	if result.Completed && !result.cleanupComplete() {
		finishErr = errors.Join(finishErr, refused("completion_cleanup"))
	}
	return finishErr
}

func (r Result) cleanupComplete() bool { return r.GatewayStopped && r.StateCleaned && r.BackendCleaned }

func (s *session) checkCustody() error {
	if s.state != nil {
		if err := s.state.verify(); err != nil {
			return err
		}
	}
	for _, d := range []*ownedDirectory{s.audit, s.spool} {
		if d != nil {
			if err := d.check(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *session) closeBackend(safe bool, result *Result) error {
	if !safe {
		return errors.Join(errCleanup, s.prepared.Retain())
	}
	err := s.prepared.Close()
	result.BackendCleaned = err == nil
	return err
}

// sessionLimit bounds a command-line session after its sign-in.
const sessionLimit = 100 * time.Second

// ExecuteFiles bounds the command's input before any operation. The CLI uses a
// private request file so unfinished inherited stdin cannot hold a session open.
func ExecuteFiles(ctx context.Context, assignmentPath, requestPath string) (Result, error) {
	a, err := ReadInput(assignmentPath, 16384)
	if err != nil {
		return Result{}, err
	}
	r, err := ReadInput(requestPath, 8192)
	if err != nil {
		return Result{}, err
	}
	return execute(ctx, a, r, sessionLimit)
}

// signInThenLimit signs the person in, then starts the session clock: the returned context's
// deadline is sessionLimit (if positive) from the moment sign-in finished.
func signInThenLimit(ctx context.Context, b *brokerSignIn, open func(context.Context, string) error, sessionLimit time.Duration) (*deviceToken, context.Context, context.CancelFunc, error) {
	device, err := b.signIn(ctx, open)
	if err != nil {
		return nil, ctx, func() {}, err
	}
	if sessionLimit <= 0 {
		return device, ctx, func() {}, nil
	}
	limited, cancel := context.WithTimeout(ctx, sessionLimit)
	return device, limited, cancel, nil
}
