package main

// Housekeeping the panel does once at start, so an install that was updated
// (the panel binary restarts, the running hashem.sh is still the old one)
// gets the same fixes a new install is written with:
//
//   - frps*/frpc* units: StartLimitIntervalSec in [Unit] and a Go memory
//     limit (frpunit below);
//   - frps*/frpc* configs: a log.level line;
//   - a size cap on the journal.
//
// Nothing here restarts a tunnel service: a unit's memory limit and a
// config's log level apply from that service's next start.

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	systemdUnitDir  = "/etc/systemd/system"
	journaldDropDir = "/etc/systemd/journald.conf.d"
)

const journaldCapConf = "# hashem: journal size cap (rewritten automatically)\n[Journal]\nSystemMaxUse=500M\nRuntimeMaxUse=200M\n"

// frpLogLevels are the levels frp accepts.
var frpLogLevels = map[string]bool{"trace": true, "debug": true, "info": true, "warn": true, "error": true}

// frpLogLevel is what frps/frpc log: "warn" unless perf.json frp_log_level
// says otherwise. At "info" frps writes a line for every user connection
// ("get a user connection"), which filled the disk of a busy hub.
func frpLogLevel() string {
	if l := strings.ToLower(strings.TrimSpace(loadPerfConfig().FRPLogLevel)); frpLogLevels[l] {
		return l
	}
	return "warn"
}

// frpLogTomlLines are the log lines of a newly written frps/frpc config.
func frpLogTomlLines() string {
	return "log.to = \"console\"\nlog.level = \"" + frpLogLevel() + "\"\n"
}

var tomlLogLevelRe = regexp.MustCompile(`(?m)^\s*log\.level\s*=`)

// tomlWithLogLevel adds a log.level line to the top-level part of an frp
// config that has none (before the first [[proxies]] table). A level that is
// already written stays: it is the operator's choice.
func tomlWithLogLevel(conf, level string) (string, bool) {
	if tomlLogLevelRe.MatchString(conf) {
		return conf, false
	}
	line := "log.level = \"" + level + "\"\n"
	if i := strings.Index(conf, "\n["); i >= 0 {
		return conf[:i+1] + line + conf[i+1:], true
	}
	if strings.HasPrefix(conf, "[") {
		return line + conf, true
	}
	if conf != "" && !strings.HasSuffix(conf, "\n") {
		conf += "\n"
	}
	return conf + line, true
}

// ensureFRPLogLevel gives every frps/frpc config without a log.level one and
// returns the files it changed.
func ensureFRPLogLevel() []string {
	var done []string
	level := frpLogLevel()
	for _, pat := range []string{"frps*.toml", "frpc*.toml"} {
		files, _ := filepath.Glob(filepath.Join(frpDir, pat))
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if out, changed := tomlWithLogLevel(string(data), level); changed {
				if writeTokenFile(f, []byte(out)) == nil {
					done = append(done, filepath.Base(f))
				}
			}
		}
	}
	return done
}

// ---- frps/frpc units ----

// frpGoMemForRAM is the GOMEMLIMIT and GOGC one frps/frpc gets on a server
// with memMB of RAM (the same tiers as hashem.sh frp_go_mem_for_ram). Without
// a limit the Go heap of a busy frpc grows until the kernel OOM-kills it;
// with one the collector works harder near the limit instead.
func frpGoMemForRAM(memMB int) (limit string, gogc int) {
	switch {
	case memMB <= 0:
		return "300MiB", 40
	case memMB <= 1250:
		return "300MiB", 40
	case memMB <= 2560:
		return "500MiB", 40
	case memMB <= 4200:
		return "900MiB", 40
	case memMB <= 6400:
		return "1400MiB", 45
	case memMB <= 8400:
		return "1800MiB", 50
	case memMB <= 16500:
		return "2500MiB", 50
	}
	return "4000MiB", 50
}

// hostMemMB is the server's RAM in MB (0 when unknown); a var for tests.
var hostMemMB = func() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, "MemTotal:") {
			var kb int
			_, _ = fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(l, "MemTotal:")), "%d", &kb)
			return kb / 1024
		}
	}
	return 0
}

// frpUnitEnvLines are the [Service] lines of a new frps/frpc unit.
func frpUnitEnvLines() string {
	limit, gogc := frpGoMemForRAM(hostMemMB())
	return fmt.Sprintf("Environment=GOMEMLIMIT=%s\nEnvironment=GOGC=%d\n", limit, gogc)
}

var startLimitRe = regexp.MustCompile(`^StartLimit(IntervalSec|Interval|Burst)=`)

// unitStartLimitFix moves the start limit where systemd reads it. In
// [Service] the key is ignored ("Unknown key name 'StartLimitIntervalSec' in
// section 'Service'") and the default limit applies. Every copy goes and
// [Unit] gets StartLimitIntervalSec=0: the service never gives up restarting,
// which is what the ignored lines left it doing.
func unitStartLimitFix(unit string) string {
	var out []string
	done := false
	for _, l := range strings.Split(unit, "\n") {
		if startLimitRe.MatchString(l) {
			continue
		}
		out = append(out, l)
		if !done && strings.TrimSpace(l) == "[Unit]" {
			out = append(out, "StartLimitIntervalSec=0")
			done = true
		}
	}
	return strings.Join(out, "\n")
}

// unitEnvDefault adds Environment=name=value under [Service] unless the unit
// already sets name (a value the operator wrote stays).
func unitEnvDefault(unit, name, value string) string {
	for _, l := range strings.Split(unit, "\n") {
		if strings.HasPrefix(l, "Environment=") && regexp.MustCompile(`(^|[\s"=])`+regexp.QuoteMeta(name)+`=`).MatchString(strings.TrimPrefix(l, "Environment")) {
			return unit
		}
	}
	return strings.Replace(unit, "[Service]", "[Service]\nEnvironment="+name+"="+value, 1)
}

// frpUnitFixed is an frps/frpc unit with the start limit in [Unit] and the Go
// memory limit for a server with memMB of RAM.
func frpUnitFixed(unit string, memMB int) string {
	limit, gogc := frpGoMemForRAM(memMB)
	unit = unitStartLimitFix(unit)
	unit = unitEnvDefault(unit, "GOMEMLIMIT", limit)
	return unitEnvDefault(unit, "GOGC", fmt.Sprint(gogc))
}

// ensureFRPUnitFiles fixes every frps*/frpc* unit file and returns the ones
// it changed. The caller reloads systemd.
func ensureFRPUnitFiles() []string {
	var done []string
	mem := hostMemMB()
	for _, pat := range []string{"frps*.service", "frpc*.service"} {
		files, _ := filepath.Glob(filepath.Join(systemdUnitDir, pat))
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if out := frpUnitFixed(string(data), mem); out != string(data) {
				if os.WriteFile(f, []byte(out), 0644) == nil {
					done = append(done, filepath.Base(f))
				}
			}
		}
	}
	return done
}

// ensureJournaldCap writes the journal size cap; true when the file changed.
// The smaller cap `hashem free-ram` wrote is kept.
func ensureJournaldCap() bool {
	path := filepath.Join(journaldDropDir, "99-hashem.conf")
	if cur, err := os.ReadFile(path); err == nil {
		if string(cur) == journaldCapConf || strings.HasPrefix(string(cur), "# hashem free-ram") {
			return false
		}
	}
	if err := os.MkdirAll(journaldDropDir, 0755); err != nil {
		return false
	}
	return os.WriteFile(path, []byte(journaldCapConf), 0644) == nil
}

var housekeepingOnce sync.Once

// startupHousekeeping runs the fixes above once, shortly after the panel is up.
func startupHousekeeping() {
	if runtime.GOOS != "linux" {
		return
	}
	housekeepingOnce.Do(func() {
		go func() {
			time.Sleep(5 * time.Second)
			if units := ensureFRPUnitFiles(); len(units) > 0 {
				_ = runSystemctl("daemon-reload")
				log.Printf("[housekeeping] frp units updated (start limit, Go memory limit; applies at their next start): %s", strings.Join(units, ", "))
			}
			if confs := ensureFRPLogLevel(); len(confs) > 0 {
				log.Printf("[housekeeping] log.level = %q written to %s (applies when that service next restarts)", frpLogLevel(), strings.Join(confs, ", "))
			}
			if ensureJournaldCap() {
				_ = exec.Command("systemctl", "restart", "systemd-journald").Run()
				log.Printf("[housekeeping] journal capped at 500M (%s)", filepath.Join(journaldDropDir, "99-hashem.conf"))
			}
			pruneTunnelLinks()
		}()
	})
}
