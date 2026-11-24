package main

import "testing"

func TestProtectMemoryMakesTheProcessUndumpable(t *testing.T) {
	if err := protectMemory(); err != nil {
		t.Fatal(err)
	}
	if dumpable() {
		t.Fatal("the gateway process is still dumpable")
	}
}
