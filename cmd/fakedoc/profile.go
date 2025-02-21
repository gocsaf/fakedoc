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
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/jessevdk/go-flags"
)

type profileFlags struct {
	// CpuProfile is the file name of the cpu profile.
	CpuProfile string `long:"cpuprofile" description:"Name of the profile file. If empty (default) no profile file is written."`
	// MemProfile is the file name of the memory profile.
	MemProfile string `long:"memprofile" description:"Name of the memory profile file. If empty (default) no memory profile file is written."`
}

// addProfileFlags adds flags for the profiler to the command line parser.
func addProfileFlags(parser *flags.Parser) (*profileFlags, error) {
	pf := profileFlags{}
	_, err := parser.AddGroup("Profile flags", "Configuration for profile collection", &pf)
	if err != nil {
		return nil, err
	}
	return &pf, nil
}

// profile create cpu and/or mery profile files for the given function.
func (pf *profileFlags) profile(fn func() error) error {
	if pf.CpuProfile != "" {
		f, err := os.Create(pf.CpuProfile)
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
	if pf.MemProfile != "" {
		f, err := os.Create(pf.MemProfile)
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
