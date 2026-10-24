package main

// gre-panel doctor: the Diagnostics tab from the terminal. `hashem doctor fix`
// runs it so the terminal repair is the panel's Quick Repair (MTU, forwarding,
// FRP limits, GRE interface, stopped engine), not only the sysctl tuning.

import (
	"fmt"
	"io"
	"os"
)

func cliDoctor(args []string) int {
	sub := "check"
	if len(args) > 0 {
		sub = args[0]
	}
	if sub != "check" && sub != "fix" {
		fmt.Fprintln(os.Stderr, "Usage: gre-panel doctor [check | fix]")
		return 2
	}
	if !cliStart() {
		return 1
	}
	loadLicenseFromDisk()
	if !hasPro(proDiagnostics) {
		fmt.Fprintln(os.Stderr, "Diagnostics is a Hashem Pro feature. Activate the license first: hashem license activate <KEY>")
		return 1
	}
	return runDoctorCLI(os.Stdout, sub == "fix")
}

// runDoctorCLI prints a diagnosis and, with fix, runs Quick Repair and
// diagnoses again.
func runDoctorCLI(out io.Writer, fix bool) int {
	// Quick Repair saves the path MTU the last diagnosis measured, so the
	// diagnosis runs first, as it does in the tab.
	printDoctorReport(out, doctorRefresh())
	if !fix {
		return 0
	}
	fmt.Fprintln(out, "\nRepair:")
	applied, _ := applyFixesFn()["applied"].([]string)
	if len(applied) == 0 {
		fmt.Fprintln(out, "  nothing to change")
	}
	for _, a := range applied {
		fmt.Fprintln(out, "  [OK] "+a)
	}
	fmt.Fprintln(out)
	printDoctorReport(out, doctorRefresh()) // a new run: doctorRefresh reuses only reports newer than the call
	return 0
}

func printDoctorReport(out io.Writer, rep *doctorReport) {
	if !rep.Configured {
		fmt.Fprintln(out, "Diagnosis: no tunnel is set up on this server yet")
		return
	}
	fmt.Fprintf(out, "Diagnosis: %s (score %d/100)\n", rep.Rating, rep.Score)
	if len(rep.Findings) == 0 {
		fmt.Fprintln(out, "  [OK] no problems found")
	}
	for _, f := range rep.Findings {
		fmt.Fprintf(out, "  [!] %s: %s\n", f.Severity, f.Title)
		if f.Fix != "" {
			fmt.Fprintf(out, "      fix: %s\n", f.Fix)
		}
	}
}
