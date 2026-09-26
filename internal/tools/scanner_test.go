package tools

import (
	"strings"
	"testing"

	"github.com/sentinel-x/sentinel-x/internal/config"
)

// The shipped defaults must never leave a value-taking flag without its value.
// nmap consumes the *next* argument as the duration in that case and aborts
// with "Bogus --host-timeout argument specified", which broke every default
// port scan.
func TestDefaultNmapDefaultsHaveNoDanglingFlags(t *testing.T) {
	cfg := config.Default()
	valueFlags := map[string]bool{
		"--host-timeout": true, "-p": true, "--script": true, "--max-retries": true,
		"--min-parallelism": true, "--top-ports": true, "--source-port": true,
	}
	fields := cfg.NmapDefaults
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if !valueFlags[f] {
			continue
		}
		if i+1 >= len(fields) {
			t.Errorf("flag %q in NmapDefaults has no value; the next argument would be consumed as its duration", f)
			continue
		}
		next := fields[i+1]
		if strings.HasPrefix(next, "-") {
			t.Errorf("flag %q in NmapDefaults is followed by %q, so nmap reads the flag as a duration", f, next)
		}
	}
}

func TestDropFlagRemovesEveryOccurrenceAndItsValue(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"absent", []string{"-sV", "-Pn", "10.0.0.1"}, []string{"-sV", "-Pn", "10.0.0.1"}},
		{"once", []string{"--host-timeout", "5m", "-sV"}, []string{"-sV"}},
		{"twice", []string{"-sV", "--host-timeout", "5m", "-n", "--host-timeout", "9m"}, []string{"-sV", "-n"}},
		{"trailing with no value", []string{"-sV", "--host-timeout"}, []string{"-sV"}},
		{"equals form", []string{"-sV", "--host-timeout=5m"}, []string{"-sV", "--host-timeout=5m"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dropFlag(c.in, "--host-timeout")
			if strings.Join(got, " ") != strings.Join(c.want, " ") {
				t.Errorf("dropFlag = %v, want %v", got, c.want)
			}
		})
	}
}

// After the drop, exactly one --host-timeout with a real duration must remain.
func TestHostTimeoutIsAppendedExactlyOnce(t *testing.T) {
	cfg := config.Default()
	// Simulate an operator who also set the flag in their own defaults.
	operator := append(append([]string{}, cfg.NmapDefaults...), "--host-timeout", "99m")
	args := dropFlag(operator, "--host-timeout")
	args = append(args, "--host-timeout", "60000ms")

	var seen int
	for i, a := range args {
		if a != "--host-timeout" {
			continue
		}
		seen++
		if i+1 >= len(args) {
			t.Fatal("--host-timeout has no value")
		}
		if v := args[i+1]; v != "60000ms" {
			t.Errorf("--host-timeout value = %q, want the computed 60000ms", v)
		}
	}
	if seen != 1 {
		t.Errorf("--host-timeout appears %d times, want exactly 1", seen)
	}
}
