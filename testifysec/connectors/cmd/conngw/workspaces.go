package main

import (
	"errors"
	"regexp"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// A workspace controller registers the workspaces it creates. A registered workspace has an owner
// (the controller's opaque id for a person) and a ceiling: its label never rises above the ceiling
// here, whatever the workspace asks. Reading higher content is done in a copy (a fork), a new
// workspace the controller creates and this pod seeds at the parent's label, so a workspace's level
// only changes with the user's say-so and a parent never sees what its fork reads. A workspace that
// is not registered behaves as before.
type registration struct {
	owner   string
	ceiling marking.Marking
}

// ownerID is the controller's id for a person: opaque here, printable, no separators that matter.
var ownerID = regexp.MustCompile(`^[A-Za-z0-9._:@-]{1,128}$`)

var (
	errAboveCeiling = errors.New("the call would raise this workspace above its ceiling")
	errOwner        = errors.New("the workspace belongs to another owner")
	errNotNew       = errors.New("the fork's workspace already exists")
	errUnregistered = errors.New("the workspace is not registered")
	errWriteDown    = errors.New("the ceiling does not dominate the parent's label")
)

// register records a workspace's owner and its ceiling, the join of floor and what it has already
// read, and returns the ceiling. Registering again for the same owner returns the ceiling it has.
func (l *labels) register(ws, owner string, floor marking.Marking) (marking.Marking, error) {
	if !ownerID.MatchString(owner) {
		return marking.Marking{}, errOwner
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if reg, ok := l.reg[ws]; ok {
		if reg.owner != owner {
			return marking.Marking{}, errOwner
		}
		return reg.ceiling, nil
	}
	ceiling := floor
	if label, ok := l.set[ws]; ok {
		var err error
		if ceiling, err = marking.Join(floor, label); err != nil {
			return marking.Marking{}, err
		}
	}
	if err := l.append(labelRecord{Workspace: ws, Owner: owner, Ceiling: marking.Banner(ceiling)}); err != nil {
		return marking.Marking{}, err
	}
	l.reg[ws] = registration{owner: owner, ceiling: ceiling}
	return ceiling, nil
}

// fork creates child, a workspace nothing has used, at parent's label, for the same owner, able to
// rise to ceiling. It is durable before it returns, so the child's pod, created after, can never
// call anything at a lower label than its parent. The parent is not changed.
func (l *labels) fork(parent, child, owner string, ceiling marking.Marking) (marking.Marking, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	reg, ok := l.reg[parent]
	switch {
	case !ok:
		return marking.Marking{}, errUnregistered
	case reg.owner != owner:
		return marking.Marking{}, errOwner
	case child == parent:
		return marking.Marking{}, errNotNew
	}
	if _, used := l.set[child]; used {
		return marking.Marking{}, errNotNew
	}
	if _, used := l.reg[child]; used {
		return marking.Marking{}, errNotNew
	}
	rec := labelRecord{Workspace: child, Owner: owner, Ceiling: marking.Banner(ceiling)}
	label, labelled := l.set[parent]
	if labelled {
		if !marking.Dominates(ceiling, label) {
			return marking.Marking{}, errWriteDown
		}
		rec.Label = marking.Banner(label)
	}
	if err := l.append(rec); err != nil {
		return marking.Marking{}, err
	}
	l.reg[child] = registration{owner: owner, ceiling: ceiling}
	if labelled {
		l.set[child] = label
	}
	return label, nil
}

// describe returns what this pod knows of a workspace.
func (l *labels) describe(ws string) (label marking.Marking, labelled bool, owner string, ceiling marking.Marking, registered bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	label, labelled = l.set[ws]
	reg, registered := l.reg[ws]
	return label, labelled, reg.owner, reg.ceiling, registered
}

// withinCeiling reports whether reading a connector marked m keeps the workspace within its
// ceiling. An unregistered workspace has none.
func (l *labels) withinCeiling(ws string, m marking.Marking) (marking.Marking, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	reg, ok := l.reg[ws]
	if !ok {
		return marking.Marking{}, true
	}
	next := m
	if label, ok := l.set[ws]; ok {
		var err error
		if next, err = marking.Join(label, m); err != nil {
			return reg.ceiling, false
		}
	}
	return reg.ceiling, marking.Dominates(reg.ceiling, next)
}
