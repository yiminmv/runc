//
// Copyright (C) 2020 MemVerge Inc.
//
package native

// #cgo CFLAGS: -Wall
// #include "nsops.go.h"
import "C"

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

func GetMappingRange(pid int) string {
	var buf *C.char
	defer C.free(unsafe.Pointer(buf))
	C.EnterSafeMode(C.pid_t(pid), &buf)
	ack := C.GoString(buf)
	fmt.Println(ack)

	toks := strings.Split(ack, ":")
	var rangeStart, rangeSize, rangeEnd uint64
	_, err := fmt.Sscanf(toks[2], "jemalloc_area=%x", &rangeStart)
	if err != nil {
		panic(err)
	}

	_, err = fmt.Sscanf(toks[3], "jemalloc_size=%x", &rangeSize)
	if err != nil {
		panic(err)
	}

	rangeEnd = rangeStart + rangeSize
	bypass := strconv.FormatUint(rangeStart, 16) + ":" + strconv.FormatUint(rangeEnd, 16)
	fmt.Println("Bypass-mapping: ", bypass)
	return bypass
}

func RestoreNormalMode(pid int) string {
	var buf *C.char
	defer C.free(unsafe.Pointer(buf))
	C.RestoreNormalMode(C.pid_t(pid), &buf)
	fmt.Println(C.GoString(buf))

	return C.GoString(buf)
}
