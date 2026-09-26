package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseGoMod(t *testing.T) {
	body := `module example.com/app

go 1.25.5

require (
	github.com/mark3labs/mcp-go v1.1.1
	github.com/spf13/cast v1.7.1 // indirect
)

require github.com/google/uuid v1.6.0

replace github.com/old/pkg => github.com/new/pkg v2.0.0
`
	got := parseGoMod(body)
	if len(got) != 3 {
		t.Fatalf("want 3 deps, got %d: %+v", len(got), got)
	}
	byName := map[string]dependency{}
	for _, d := range got {
		byName[d.Name] = d
	}
	if d := byName["github.com/mark3labs/mcp-go"]; d.Version != "v1.1.1" || !d.Direct {
		t.Errorf("block require parsed wrong: %+v", d)
	}
	if d := byName["github.com/spf13/cast"]; d.Direct {
		t.Errorf("// indirect must be marked transitive: %+v", d)
	}
	if d := byName["github.com/google/uuid"]; d.Version != "v1.6.0" || !d.Direct {
		t.Errorf("single-line require parsed wrong: %+v", d)
	}
	if _, present := byName["github.com/old/pkg"]; present {
		t.Error("replace directives must not be reported as dependencies")
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	body := `# comment
requests==2.31.0
flask>=2.0,<3.0  # inline comment
django[bcrypt]==4.2.0 ; python_version >= "3.8"
git+https://github.com/x/y.git#egg=z
-r other.txt
-e .
PyYAML
`
	got := parseRequirementsTxt(body)
	byName := map[string]dependency{}
	for _, d := range got {
		byName[d.Name] = d
	}
	if byName["requests"].Version != "2.31.0" {
		t.Errorf("requests: %+v", byName["requests"])
	}
	if byName["flask"].Version != "2.0" {
		t.Errorf("flask: %+v", byName["flask"])
	}
	if byName["django"].Version != "4.2.0" {
		t.Errorf("django: %+v", byName["django"])
	}
	if byName["PyYAML"].Version != "" {
		t.Errorf("a bare name must have no version: %+v", byName["PyYAML"])
	}
	for _, skip := range []string{"git+https://github.com/x/y.git#egg=z", "-r", "-e"} {
		if _, present := byName[skip]; present {
			t.Errorf("%q should have been skipped", skip)
		}
	}
}

func TestParsePackageLockBothShapes(t *testing.T) {
	v1 := `{"dependencies":{"lodash":{"version":"4.17.21","requires":{"x":"1"}},"left-pad":{"version":"1.3.0"}}}`
	if got := parsePackageLock(v1); len(got) != 2 {
		t.Errorf("v1 lockfile: want 2, got %d %+v", len(got), got)
	}
	v2 := `{"packages":{"":{"name":"root"},"node_modules/express":{"version":"4.18.2","license":"MIT"},"node_modules/debug":{"version":"2.6.9","dev":true}}}`
	got := parsePackageLock(v2)
	if len(got) != 2 {
		t.Errorf("v2 lockfile: want 2, got %d %+v", len(got), got)
	}
	for _, d := range got {
		if d.Ecosystem != "npm" {
			t.Errorf("ecosystem not set: %+v", d)
		}
	}
}

func TestParsePomAndGemAndCargo(t *testing.T) {
	pom := `<project><dependencies><dependency>
	<groupId>org.apache.logging.log4j</groupId>
	<artifactId>log4j-core</artifactId>
	<version>2.14.1</version>
	</dependency><dependency>
	<groupId>com.example</groupId><artifactId>lib</artifactId><version>${lib.version}</version>
	</dependency></dependencies></project>`
	got := parsePomXML(pom)
	if len(got) != 2 {
		t.Fatalf("pom: want 2, got %+v", got)
	}
	if got[0].Name != "org.apache.logging.log4j:log4j-core" || got[0].Version != "2.14.1" {
		t.Errorf("pom coordinate: %+v", got[0])
	}
	if got[1].Version != "" {
		t.Errorf("unresolved ${} property must yield no version: %+v", got[1])
	}

	gem := `GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.8)
    rack-session (1.0.2)
      rack

PLATFORMS
  ruby
`
	g := parseGemfileLock(gem)
	if len(g) != 2 {
		t.Fatalf("gemfile: want 2, got %+v", g)
	}

	cargo := `[[package]]
name = "openssl"
version = "0.10.55"

[[package]]
name = "from-git"
version = "1.0.0"
source = "git+https://github.com/x/y"

[[package]]
name = "serde"
version = "1.0.197"
`
	c := parseCargoLock(cargo)
	if len(c) != 2 {
		t.Fatalf("cargo: want 2 (git source skipped), got %+v", c)
	}
	for _, d := range c {
		if d.Name == "from-git" {
			t.Error("git-sourced crates cannot be version-correlated and must be skipped")
		}
	}
}

func TestVersionRangeMatching(t *testing.T) {
	cases := []struct {
		version string
		spec    string
		want    bool
	}{
		{"1.2.3", "1.2.3", true},
		{"1.2.3", "1.2.4", false},
		{"2.0.0", "*", true},
		{"2.0.0", ">=1.0", true},
		{"0.9.0", ">=1.0", false},
		{"1.5.0", ">=1.0 <2.0", true},
		{"2.0.1", ">=1.0 <2.0", false},
		{"1.10.0", ">=1.9", true},
		{"v1.2.3", "1.2.3", true},
		{"1.0.0", "<=1.0.0", true},
		{"1.0.1", "<=1.0.0", false},
	}
	for _, c := range cases {
		if got := inVersionRange(c.version, c.spec); got != c.want {
			t.Errorf("inVersionRange(%q, %q) = %v, want %v", c.version, c.spec, got, c.want)
		}
	}
}

// A naive lexicographic compare would call 1.10.0 < 1.9, which would hide
// real vulnerabilities. Guard the numeric-segment behaviour explicitly.
func TestCompareVersionsIsNumericNotLexicographic(t *testing.T) {
	if compareVersions("1.10.0", "1.9") <= 0 {
		t.Error("1.10.0 must compare greater than 1.9")
	}
	if compareVersions("1.0.0-rc1", "1.0.0") > 0 {
		t.Error("pre-release metadata must not inflate the version")
	}
}

func TestCPEVersionExtraction(t *testing.T) {
	cases := map[string]string{
		"cpe:2.3:a:vendor:product:1.2:*:*:*:*:*:*:*": "1.2",
		"cpe:2.3:a:v:p:*:*:*:*:*:*:*:*":              "*",
		"garbage":                                    "",
	}
	for cpe, want := range cases {
		if got := cpeVersion(cpe); got != want {
			t.Errorf("cpeVersion(%q) = %q, want %q", cpe, got, want)
		}
	}
}

func TestAnyProductMentions(t *testing.T) {
	products := []string{
		"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
	}
	if !anyProductMentions(products, "log4j") {
		t.Error("log4j should match")
	}
	if anyProductMentions(products, "nginx") {
		t.Error("nginx must not match log4j products")
	}
	// Underscore/hyphen normalisation is how PyPI names map to CPE names.
	if !anyProductMentions([]string{"cpe:2.3:a:p:pyyaml:5.1:*:*:*:*:*:*:*"}, "PyYAML") {
		t.Error("PyYAML should normalise to pyyaml")
	}
}

func TestBuildInventoryFindsManifests(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := dir + "/" + rel
		if err := writeFileForTest(p, body); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module x\n\nrequire github.com/a/b v1.0.0\n")
	write("requirements.txt", "requests==2.31.0\n")
	write("node_modules/pkg/package.json", `{"name":"ignored"}`)
	write(".git/config", "ignored")

	deps, files, truncated, err := buildInventory(dir, 64, 100)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("small tree should not be truncated")
	}
	if len(deps) != 2 {
		t.Fatalf("want 2 deps, got %d: %+v", len(deps), deps)
	}
	if len(files) != 2 {
		t.Errorf("want 2 manifests, got %v", files)
	}
	// node_modules must be skipped even though a json file lives there.
	if strings.Contains(strings.Join(files, ","), "node_modules") {
		t.Errorf("node_modules should have been skipped: %v", files)
	}
	// The manifest field must let a caller trace a finding back to its file.
	for _, d := range deps {
		if d.Manifest == "" {
			t.Errorf("dependency %s has no manifest attribution", d.Name)
		}
	}
}

// writeFileForTest writes body to path, creating parent directories, so a test
// can place a manifest somewhere the walker is expected to skip.
func writeFileForTest(path, body string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(body), 0o644)
}
