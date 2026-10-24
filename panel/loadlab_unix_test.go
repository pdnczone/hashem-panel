//go:build linux

package main

import "syscall"

// labLowerPriority makes the lab yield CPU to real workloads on the host.
func labLowerPriority() { _ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 19) }
