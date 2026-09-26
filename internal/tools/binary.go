package tools

// Binary hardening analysis.
//
// This is a static, read-only inspection of an executable's headers. It is the
// same class of check that the `checksec` script performs, implemented directly
// against Go's debug/{elf,pe} packages so that no external binary has to be
// allowlisted and there is nothing to execute at all.
//
// Every field reported here comes from the file's own headers. The tool opens
// the file read-only, never maps it executable, and never runs it.

import (
	"context"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// binaryHardeningTool is registered by the Platform module.
func binaryHardeningTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_binary_hardening",
		mcp.WithDescription(
			"Inspect a compiled executable (ELF, PE or Mach-O) and report its exploit-mitigation "+
				"posture: non-executable stack, position-independent code, full or partial RELRO, "+
				"stack canaries, RPATH/RUNPATH, text relocations, Control Flow Guard, ASLR, SafeSEH, "+
				"and whether the binary is stripped. Optionally audits a whole directory tree. "+
				"READ-ONLY: the file is parsed from disk and is never loaded or executed.",
		),
		mcp.WithToolTitle("SENTINEL-X Binary Hardening Audit"),
		mcp.WithString("path",
			mcp.Description("Absolute path to an executable, or a directory to audit recursively. Must be inside the configured audit roots."),
			mcp.Required(),
		),
		mcp.WithBoolean("recursive",
			mcp.Description("When path is a directory, descend into subdirectories."),
			mcp.DefaultBool(false),
		),
		mcp.WithNumber("max_files",
			mcp.Description("Maximum files to inspect when walking a directory (1-500)."),
			mcp.DefaultNumber(100),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_binary_hardening"

		path, aerr := requireArg(req, "path")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		if path == "" {
			return failf(toolName, path, start, "path is required")
		}
		if ok, why := d.Cfg.AuditPathAllowed(path); !ok {
			return fail(toolName, path, start, &ScopeError{Host: path, Reason: why})
		}

		limit := req.GetInt("max_files", 100)
		if limit < 1 {
			limit = 1
		}
		if limit > 500 {
			limit = 500
		}

		targets, truncated, err := collectBinaries(path, req.GetBool("recursive", false), limit)
		if err != nil {
			return fail(toolName, path, start, err)
		}

		var (
			out    []BinaryReport
			failed int
		)
		for _, p := range targets {
			rep, err := inspectBinary(p)
			if err != nil {
				// A non-executable or unreadable file is not a finding; it just
				// means the walk picked up something that is not a binary.
				failed++
				continue
			}
			out = append(out, rep)
		}

		res := BinaryAuditResult{
			Root:       path,
			Inspected:  len(out),
			Skipped:    failed,
			Truncated:  truncated,
			Binaries:   out,
			MethodNote: "static header analysis; no code was loaded or executed",
		}
		if len(out) == 0 {
			res.Findings = []Finding{{Severity: "info",
				Summary:  "no executables were found at the given path",
				Evidence: fmt.Sprintf("walked up to %d candidate files", limit)}}
		}
		return ok(d, toolName, path, start, nil, res)
	}

	return Tool{Tool: t, Handler: h}
}

// BinaryAuditResult aggregates a hardening sweep.
type BinaryAuditResult struct {
	Root       string         `json:"root"`
	Inspected  int            `json:"inspected"`
	Skipped    int            `json:"skipped"`
	Truncated  bool           `json:"truncated"`
	MethodNote string         `json:"method"`
	Binaries   []BinaryReport `json:"binaries"`
	Findings   []Finding      `json:"findings,omitempty"`
}

// BinaryReport is the mitigation posture of one executable.
type BinaryReport struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	// Format is one of "elf", "pe", "macho" or "unknown".
	Format string `json:"format"`
	Arch   string `json:"arch,omitempty"`
	// Mitigations maps a mitigation name to whether it is present. A mitigation
	// that does not apply to the format is reported as "n/a".
	Mitigations map[string]string `json:"mitigations"`
	// Libraries lists DT_NEEDED (ELF) or imported DLLs (PE).
	Libraries []string `json:"libraries,omitempty"`
	// RPATH/RUNPATH present, which lets a hijacked library load silently.
	RPath       string    `json:"rpath,omitempty"`
	TextRelocs  bool      `json:"text_relocations,omitempty"`
	Stripped    bool      `json:"stripped"`
	SymbolCount int       `json:"symbol_count"`
	Findings    []Finding `json:"findings,omitempty"`
	// Hardened is true when every mitigation that applies is present.
	Hardened bool `json:"hardened"`
}

// collectBinaries walks path and returns the files worth inspecting.
func collectBinaries(root string, recursive bool, limit int) (files []string, truncated bool, err error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, false, fmt.Errorf("cannot inspect %s: %w", root, err)
	}
	if !st.IsDir() {
		return []string{root}, false, nil
	}

	err = filepath.WalkDir(root, func(p string, entry os.DirEntry, err error) error {
		if err != nil {
			// An unreadable subtree is reported by the caller as a skip rather
			// than aborting the whole sweep.
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if p != root && !recursive {
				return filepath.SkipDir
			}
			if p != root && shouldSkipDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isExecutableFile(entry) {
			return nil
		}
		files = append(files, p)
		if len(files) >= limit {
			truncated = true
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return files, truncated, nil
	}
	return files, truncated, nil
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "testdata", "__pycache__", ".venv", "target", "dist", "build":
		return true
	}
	return false
}

func isExecutableFile(e os.DirEntry) bool {
	if e.IsDir() {
		return false
	}
	info, err := e.Info()
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

// inspectBinary dispatches on file magic rather than extension, because a
// mislabelled or extensionless binary is exactly the case worth catching.
func inspectBinary(path string) (BinaryReport, error) {
	st, err := os.Stat(path)
	if err != nil {
		return BinaryReport{}, err
	}
	rep := BinaryReport{
		Path:        path,
		Size:        st.Size(),
		Mitigations: map[string]string{},
	}

	magic, err := readMagic(path)
	if err != nil {
		return BinaryReport{}, err
	}

	switch {
	case len(magic) >= 4 && magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F':
		if err := inspectELF(path, &rep); err != nil {
			return BinaryReport{}, err
		}
	case len(magic) >= 2 && magic[0] == 'M' && magic[1] == 'Z':
		if err := inspectPE(path, &rep); err != nil {
			return BinaryReport{}, err
		}
	case len(magic) >= 4 && binary.LittleEndian.Uint32(magic) == 0xfeedfacf,
		len(magic) >= 4 && binary.LittleEndian.Uint32(magic) == 0xfeedface,
		len(magic) >= 4 && binary.BigEndian.Uint32(magic) == 0xfeedface,
		len(magic) >= 4 && binary.LittleEndian.Uint32(magic) == 0xcffaedfe,
		len(magic) >= 4 && binary.LittleEndian.Uint32(magic) == 0xcefaedfe:
		rep.Format = "macho"
		rep.Mitigations["exploit_mitigations"] = "n/a"
		rep.Hardened = false
		rep.Findings = append(rep.Findings, Finding{Severity: "info",
			Summary:   "Mach-O binary; this tool analyses ELF and PE mitigations only",
			Evidence:  path,
			Remediate: "run the platform's own codesign/otool checks for a macOS binary"})
	default:
		return BinaryReport{}, fmt.Errorf("%s is not a recognised executable format", path)
	}
	return rep, nil
}

func readMagic(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 4)
	n, err := f.Read(buf)
	if n == 0 && err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	return buf[:n], nil
}

// inspectELF populates the mitigation map from ELF program headers and the
// dynamic section.
func inspectELF(path string, rep *BinaryReport) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("cannot parse ELF %s: %w", path, err)
	}
	defer f.Close()

	rep.Format = "elf"
	rep.Arch = elfArch(f)
	switch f.Class {
	case elf.ELFCLASS64:
		rep.Arch += " (64-bit)"
	case elf.ELFCLASS32:
		rep.Arch += " (32-bit)"
	}

	// PIE: a position-independent executable is ET_DYN, while a plain
	// non-PIE executable is ET_EXEC.
	switch f.Type {
	case elf.ET_DYN:
		rep.Mitigations["position_independent"] = "yes"
	case elf.ET_EXEC:
		rep.Mitigations["position_independent"] = "no"
	default:
		rep.Mitigations["position_independent"] = "unknown"
	}

	// NX: the GNU_STACK program header carries the stack permissions. An
	// executable stack defeats NX and is a serious finding.
	nx := "unknown"
	hasStack := false
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_STACK {
			hasStack = true
			if prog.Flags&elf.PF_X != 0 {
				nx = "no (stack is executable)"
			} else {
				nx = "yes"
			}
		}
	}
	if !hasStack {
		nx = "yes (no PT_GNU_STACK header; stack is non-executable by default)"
	}
	rep.Mitigations["non_executable_stack"] = nx

	// RELRO: PT_GNU_RELRO marks the relro region; BIND_NOW (either the
	// DT_FLAGS or the DF_ dynamic flag) upgrades it from partial to full.
	relro := "no"
	bindNow := false
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_RELRO {
			relro = "partial"
		}
	}
	for _, tag := range []elf.DynTag{elf.DT_BIND_NOW, elf.DT_FLAGS, elf.DT_FLAGS_1} {
		val, err := f.DynValue(tag)
		if err != nil || len(val) == 0 {
			continue
		}
		v := val[0]
		switch tag {
		case elf.DT_BIND_NOW:
			bindNow = v != 0
		case elf.DT_FLAGS:
			// DF_BIND_NOW == 0x8
			if v&0x8 != 0 {
				bindNow = true
			}
		case elf.DT_FLAGS_1:
			// DF_1_NOW == 0x1
			if v&0x1 != 0 {
				bindNow = true
			}
		}
	}
	if relro == "partial" && bindNow {
		rep.Mitigations["relro"] = "full"
	} else if relro == "partial" {
		rep.Mitigations["relro"] = "partial"
	} else {
		rep.Mitigations["relro"] = "no"
	}

	// A canary shows up as an imported __stack_chk_fail symbol.
	canary := "no"
	if hasSymbol(f, "__stack_chk_fail") || hasSymbol(f, "__stack_chk_guard") {
		canary = "yes"
	}
	rep.Mitigations["stack_canary"] = canary

	// Libraries and search path.
	if libs, err := f.ImportedLibraries(); err == nil {
		sort.Strings(libs)
		rep.Libraries = libs
	}
	// DynString returns one entry per colon-separated element of the tag.
	var searches []string
	if rpath, err := f.DynString(elf.DT_RPATH); err == nil {
		searches = append(searches, rpath...)
	}
	if runpath, err := f.DynString(elf.DT_RUNPATH); err == nil {
		searches = append(searches, runpath...)
	}
	rep.RPath = strings.Join(searches, " ")

	// Text relocations force the loader to make .text writable at load time,
	// which undermines W^X.
	if v, err := f.DynValue(elf.DT_TEXTREL); err == nil && len(v) > 0 && v[0] != 0 {
		rep.TextRelocs = true
	}

	// Stripped binaries lack a .symtab.
	rep.Stripped = f.Section(".symtab") == nil
	if !rep.Stripped {
		if syms, err := f.Symbols(); err == nil {
			rep.SymbolCount = len(syms)
		}
	}

	finaliseELF(rep)
	return nil
}

// hasSymbol reports whether a symbol is present in either the dynamic or the
// static symbol table.
func hasSymbol(f *elf.File, name string) bool {
	if syms, err := f.DynamicSymbols(); err == nil {
		for _, s := range syms {
			if s.Name == name {
				return true
			}
		}
	}
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if s.Name == name {
				return true
			}
		}
	}
	return false
}

func elfArch(f *elf.File) string {
	switch f.Machine {
	case elf.EM_X86_64:
		return "x86-64"
	case elf.EM_386:
		return "x86"
	case elf.EM_AARCH64:
		return "aarch64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_RISCV:
		return "riscv"
	case elf.EM_PPC64:
		return "ppc64"
	case elf.EM_S390:
		return "s390x"
	case elf.EM_MIPS:
		return "mips"
	default:
		return fmt.Sprintf("machine(%d)", f.Machine)
	}
}

// finaliseELF turns raw mitigation values into findings and a verdict.
func finaliseELF(rep *BinaryReport) {
	mit := rep.Mitigations
	hardened := true

	// Non-executable stack.
	switch mit["non_executable_stack"] {
	case "no (stack is executable)":
		hardened = false
		rep.Findings = append(rep.Findings, Finding{Severity: "high",
			Summary:   "executable stack allows shellcode injection onto the stack",
			Evidence:  "PT_GNU_STACK has PF_X set",
			Remediate: "rebuild with -Wl,-z,noexecstack (or drop -z execstack)"})
	default:
		rep.Findings = append(rep.Findings, Finding{Severity: "info",
			Summary:  "non-executable stack (NX) is enabled",
			Evidence: mit["non_executable_stack"]})
	}

	// PIE / ASLR.
	if mit["position_independent"] == "no" {
		hardened = false
		rep.Findings = append(rep.Findings, Finding{Severity: "medium",
			Summary:   "not position-independent; fixed load address weakens ASLR",
			Evidence:  "ELF type is ET_EXEC",
			Remediate: "rebuild as a PIE (-pie / -fPIE)"})
	}

	// RELRO.
	switch mit["relro"] {
	case "no":
		hardened = false
		rep.Findings = append(rep.Findings, Finding{Severity: "high",
			Summary:   "no RELRO; the GOT stays writable and is a common exploitation target",
			Evidence:  "no PT_GNU_RELRO segment",
			Remediate: "rebuild with -Wl,-z,relro"})
	case "partial":
		hardened = false
		rep.Findings = append(rep.Findings, Finding{Severity: "low",
			Summary:   "partial RELRO; BIND_NOW is missing so the GOT can be rewritten after startup",
			Evidence:  "PT_GNU_RELRO present without BIND_NOW",
			Remediate: "rebuild with -Wl,-z,now to get full RELRO"})
	}

	// Canary.
	if mit["stack_canary"] == "no" {
		rep.Findings = append(rep.Findings, Finding{Severity: "low",
			Summary:   "no stack canary detected",
			Evidence:  "no __stack_chk_fail import",
			Remediate: "build with -fstack-protector-strong"})
	}

	// RPATH.
	if rep.RPath != "" {
		hardened = false
		rep.Findings = append(rep.Findings, Finding{Severity: "medium",
			Summary:   "RPATH/RUNPATH is set; a writable directory on the path can load a hijacked library",
			Evidence:  rep.RPath,
			Remediate: "remove RPATH/RUNPATH, or ensure no listed directory is writable by non-root"})
	}

	// Text relocations.
	if rep.TextRelocs {
		hardened = false
		rep.Findings = append(rep.Findings, Finding{Severity: "medium",
			Summary:   "text relocations force the loader to mark code pages writable at load time",
			Evidence:  "DT_TEXTREL is set",
			Remediate: "rebuild without -z notext / with -Wl,-z,text"})
	}

	rep.Hardened = hardened
}

// PE constants that debug/pe does not export. debug/pe provides the
// IMAGE_DLLCHARACTERISTICS_* values but not the file-characteristics or
// data-directory indices, so those are declared here.
const (
	imageFileRelocsStripped = 0x0001
	imageFileDebugStripped  = 0x0200
	imageDirEntryLoadConfig = 10
)

// inspectPE populates the mitigation map from the PE optional header.
func inspectPE(path string, rep *BinaryReport) error {
	f, err := pe.Open(path)
	if err != nil {
		return fmt.Errorf("cannot parse PE %s: %w", path, err)
	}
	defer f.Close()

	rep.Format = "pe"
	rep.Arch = peArch(f)

	// A stripped PE has no relocation or debug information, which is a mild
	// hardening signal and matches what tools like checksec report.
	char := f.FileHeader.Characteristics
	rep.Stripped = char&(imageFileRelocsStripped|imageFileDebugStripped) != 0

	// Read DllCharacteristics and the load-config directory from whichever
	// optional-header variant this binary uses.
	var dllChars uint16
	var loadCfg pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dllChars = oh.DllCharacteristics
		loadCfg = oh.DataDirectory[imageDirEntryLoadConfig]
	case *pe.OptionalHeader64:
		dllChars = oh.DllCharacteristics
		loadCfg = oh.DataDirectory[imageDirEntryLoadConfig]
	default:
		return fmt.Errorf("%s has no optional header", path)
	}

	set := func(name string, present bool, absent string) {
		if present {
			rep.Mitigations[name] = "yes"
		} else {
			rep.Mitigations[name] = absent
		}
	}
	set("aslr", dllChars&pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0, "no")
	set("non_executable_stack", dllChars&pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0, "no (DEP not declared)")
	set("control_flow_guard", dllChars&pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0, "no")
	set("high_entropy_aslr", dllChars&pe.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0, "no")
	set("code_integrity", dllChars&pe.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0, "no")

	// The load config is where the SafeSEH handler table and the CFG function
	// table live; its absence means there is no SEH hardening metadata.
	if loadCfg.VirtualAddress != 0 && loadCfg.Size != 0 {
		rep.Mitigations["seh_hardening"] = "yes (load config present)"
	} else {
		rep.Mitigations["seh_hardening"] = "no (no load config directory)"
	}

	hardened := true
	if rep.Mitigations["aslr"] != "yes" {
		hardened = false
		rep.Findings = append(rep.Findings, Finding{Severity: "high",
			Summary:   "ASLR is disabled",
			Evidence:  "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is not set",
			Remediate: "relink with /DYNAMICBASE"})
	}
	if rep.Mitigations["non_executable_stack"] != "yes" {
		hardened = false
		rep.Findings = append(rep.Findings, Finding{Severity: "high",
			Summary:   "DEP/NX is not declared",
			Evidence:  "IMAGE_DLLCHARACTERISTICS_NX_COMPAT is not set",
			Remediate: "relink with /NXCOMPAT"})
	}
	if rep.Mitigations["control_flow_guard"] != "yes" {
		rep.Findings = append(rep.Findings, Finding{Severity: "medium",
			Summary:   "Control Flow Guard is off",
			Evidence:  "IMAGE_DLLCHARACTERISTICS_GUARD_CF is not set",
			Remediate: "compile with /guard:cf"})
	}
	rep.Hardened = hardened
	return nil
}

func peArch(f *pe.File) string {
	switch f.FileHeader.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86-64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_ARM, pe.IMAGE_FILE_MACHINE_ARMNT:
		return "arm"
	default:
		return fmt.Sprintf("machine(0x%x)", f.FileHeader.Machine)
	}
}
