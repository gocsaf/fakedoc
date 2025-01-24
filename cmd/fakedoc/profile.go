// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

//go:build profile

package main

import (
	"errors"
	"flag"
	"os"
	"runtime"
	"runtime/pprof"
)

const (
	cpuProfileDocumentation = `
Name of the profile file. If empty (default) no profile file is written.
`
	memProfileDocumentation = `
Name of the memory profile file. If empty (default) no memory profile file is written.
`
)

type profileFlags struct {
	// cpuProfile is the file name of the cpu profile.
	cpuProfile string
	// memProfile is the file name of the memory profile.
	memProfile string
}

// addProfileFlags adds flags for the profiler to the command line parser.
func addProfileFlags() *profileFlags {
	pf := profileFlags{}
	flag.StringVar(&pf.cpuProfile, "cpuprofile", "", cpuProfileDocumentation)
	flag.StringVar(&pf.memProfile, "memprofile", "", memProfileDocumentation)
	return &pf
}

// profile create cpu and/or mery profile files for the given function.
func (pf *profileFlags) profile(fn func() error) error {
	if pf.cpuProfile != "" {
		f, err := os.Create(pf.cpuProfile)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()
	}
	ret := fn()
	if pf.memProfile != "" {
		f, err := os.Create(pf.memProfile)
		if err != nil {
			return errors.Join(ret, err)
		}
		defer f.Close()
		runtime.GC() // get up-to-date statistics.
		if err := pprof.WriteHeapProfile(f); err != nil {
			return errors.Join(ret, err)
		}
	}
	return ret
}
