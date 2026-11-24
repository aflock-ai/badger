package main

import (
	"context"
	"errors"
	"time"
)

// Registered before creation, this scope is recoverable by its random name
// even if Docker commits a create operation then loses/malforms the response.
// Never delete an object without both the exact operation and policy labels.
func (e *engine) cleanupOwned(name, volumeName, policyHash string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	containerErr := e.removeOwnedContainer(ctx, name, policyHash)
	volumeErr := e.removeOwnedVolume(ctx, volumeName, policyHash)
	return errors.Join(containerErr, volumeErr)
}
func (e *engine) removeOwnedContainer(ctx context.Context, name, policyHash string) error {
	actual, err := e.inspect(ctx, name)
	if engineAbsent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !validID(actual.ID) || actual.Name != "/"+name || actual.Config.Labels["io.testifysec.hardened.operation"] != name || actual.Config.Labels["io.testifysec.hardened.policy"] != policyHash {
		return deny("cleanup_failed", "Worker ownership could not be established")
	}
	err = e.call(ctx, "DELETE", "/containers/"+actual.ID+"?force=1&v=1", nil, nil)
	if err != nil && !engineAbsent(err) {
		return err
	}
	_, err = e.inspect(ctx, actual.ID)
	if engineAbsent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return deny("cleanup_failed", "Worker removal could not be confirmed")
}
func (e *engine) removeOwnedVolume(ctx context.Context, name, policyHash string) error {
	var actual struct {
		Name, Driver, Scope string
		Labels              map[string]string
	}
	err := e.call(ctx, "GET", "/volumes/"+name, nil, &actual)
	if engineAbsent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if actual.Name != name || actual.Driver != "local" || actual.Scope != "local" || actual.Labels["io.testifysec.hardened.workspace"] != name || actual.Labels["io.testifysec.hardened.policy"] != policyHash {
		return deny("cleanup_failed", "Workspace volume ownership could not be established")
	}
	err = e.call(ctx, "DELETE", "/volumes/"+name, nil, nil)
	if err != nil && !engineAbsent(err) {
		return err
	}
	err = e.call(ctx, "GET", "/volumes/"+name, nil, &actual)
	if engineAbsent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return deny("cleanup_failed", "Workspace volume removal could not be confirmed")
}
