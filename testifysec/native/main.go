package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"

import "unsafe"

// RookeryVerify accepts a borrowed buffer for the duration of this call.
// The returned C allocation must be released exactly once with RookeryFree.
// Invalid native pointers are caller errors, not recoverable JSON errors.
//
//export RookeryVerify
func RookeryVerify(input unsafe.Pointer, length C.size_t) (output *C.char) {
	defer func() {
		if recover() != nil {
			output = C.CString(`{"abiVersion":1,"ok":false,"error":"native verifier failure"}`)
		}
	}()
	if input == nil || length == 0 || length > maxRequest {
		return C.CString(`{"abiVersion":1,"ok":false,"error":"invalid request size"}`)
	}
	return C.CString(string(verifyJSON(C.GoBytes(input, C.int(length)))))
}

//export RookeryFree
func RookeryFree(output unsafe.Pointer) { C.free(output) }

//export RookeryABIVersion
func RookeryABIVersion() C.uint32_t { return 1 }

func main() {}
