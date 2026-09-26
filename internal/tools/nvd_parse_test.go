package tools

import (
	"encoding/json"
	"testing"
)

// The NVD 2.0 API returns each metric family as an array, and reference tags as
// an array. Typing either as a scalar made json.Unmarshal reject the whole
// document, and the lookup then answered every request with a placeholder
// record that looked like a successful, empty result.
const nvdArrayShapedRecord = `{
  "id": "CVE-2018-15473",
  "published": "2018-07-19T16:29:00.000",
  "lastModified": "2024-11-01T12:00:00.000",
  "vulnStatus": "Modified",
  "descriptions": [
    {"lang": "en", "value": "OpenSSH before 7.6 allows enumeration of usernames."},
    {"lang": "es", "value": "descripcion en espanol"}
  ],
  "metrics": {
    "cvssMetricV31": [
      {
        "source": "nvd@nist.gov",
        "type": "Primary",
        "cvssData": {
          "baseScore": 5.3,
          "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
          "baseSeverity": "MEDIUM"
        }
      }
    ]
  },
  "weaknesses": [{"description": [{"value": "CWE-203"}]}],
  "configurations": [
    {"nodes": [
      {"operator": "OR", "negate": false, "cpeMatch": [
        {"vulnerable": true, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"},
        {"vulnerable": false, "criteria": "cpe:2.3:o:debian:debian_linux:8.0:*:*:*:*:*:*:*"}
      ]}
    ]}
  ],
  "references": [
    {"url": "https://example.com/patch", "source": "security@openssh.org", "tags": ["Patch", "Vendor Advisory"]},
    {"url": "https://example.com/poc", "source": "exploit-db.com", "tags": ["Exploit", "Third Party Advisory"]},
    {"url": "https://example.com/mention", "source": "nvd@nist.gov", "tags": ["VDB Entry"]}
  ]
}`

func decodeRecord(t *testing.T, raw string) json.RawMessage {
	t.Helper()
	var wrapper struct {
		Vulnerabilities []struct {
			CVE json.RawMessage `json:"cve"`
		} `json:"vulnerabilities"`
	}
	doc := `{"totalResults":1,"vulnerabilities":[{"cve":` + raw + `}]}`
	if err := json.Unmarshal([]byte(doc), &wrapper); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	return wrapper.Vulnerabilities[0].CVE
}

func TestAdaptCVEParsesArrayShapedNVDRecord(t *testing.T) {
	c, err := adaptCVE(decodeRecord(t, nvdArrayShapedRecord))
	if err != nil {
		t.Fatalf("adaptCVE returned an error for a well-formed NVD record: %v", err)
	}
	if c.ID != "CVE-2018-15473" {
		t.Errorf("id = %q, want CVE-2018-15473", c.ID)
	}
	if c.CVSS != 5.3 {
		t.Errorf("cvss = %v, want 5.3", c.CVSS)
	}
	if c.CVSSVersion != "3.1" {
		t.Errorf("cvss version = %q, want 3.1", c.CVSSVersion)
	}
	if c.Severity != "MEDIUM" {
		t.Errorf("severity = %q, want MEDIUM", c.Severity)
	}
	if c.Description != "OpenSSH before 7.6 allows enumeration of usernames." {
		t.Errorf("description = %q, want the English text", c.Description)
	}
	if len(c.Weakness) != 1 || c.Weakness[0] != "CWE-203" {
		t.Errorf("weakness = %v, want [CWE-203]", c.Weakness)
	}
}

func TestAdaptCVEKeepsOnlyVulnerableCPEMatches(t *testing.T) {
	c, err := adaptCVE(decodeRecord(t, nvdArrayShapedRecord))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Products) != 1 {
		t.Fatalf("products = %v, want only the vulnerable CPE", c.Products)
	}
	if c.Products[0] != "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*" {
		t.Errorf("product = %q, want the openbsd openssh CPE", c.Products[0])
	}
}

// A reference can be a patch and an exploit at the same time. Classifying on the
// first matching tag reported fixes that ship alongside a proof of concept as
// having no patch at all.
func TestAdaptCVESeparatesPatchAndExploitReferences(t *testing.T) {
	c, err := adaptCVE(decodeRecord(t, nvdArrayShapedRecord))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.PatchRefs) != 1 {
		t.Errorf("patch refs = %d, want 1", len(c.PatchRefs))
	}
	if len(c.ExploitRefs) != 1 {
		t.Fatalf("exploit refs = %d, want 1", len(c.ExploitRefs))
	}
	if c.ExploitRefs[0].URL != "https://example.com/poc" {
		t.Errorf("exploit ref = %q, want the poc link", c.ExploitRefs[0].URL)
	}
	if c.ExploitRefs[0].Kind != "exploit" {
		t.Errorf("exploit ref kind = %q, want exploit", c.ExploitRefs[0].Kind)
	}
}

// An unreadable response must be an error. Returning it as a result made the
// tool look like it had checked and found nothing.
func TestAdaptCVERejectsUnreadableRecords(t *testing.T) {
	for name, raw := range map[string]string{
		"no id":         `{"published":"2021-01-01T00:00:00.000"}`,
		"wrong shape":   `{"id":"CVE-1-1","metrics":{"cvssMetricV31":"nope"}}`,
		"not an object": `[]`,
	} {
		if _, err := adaptCVE(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: adaptCVE accepted an unreadable record", name)
		}
	}
}

// The API is not consistent about single-object versus array across versions.
func TestNVDMetricListAcceptsBothShapes(t *testing.T) {
	var list nvdMetricList
	if err := json.Unmarshal([]byte(`{"type":"Primary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}`), &list); err != nil {
		t.Fatalf("single object rejected: %v", err)
	}
	m, ok := list.primary()
	if !ok || m.CVSSData.BaseScore != 9.8 || m.Severity() != "CRITICAL" {
		t.Errorf("single object: got %+v ok=%v", m, ok)
	}
	if err := json.Unmarshal([]byte(`null`), &list); err != nil || list != nil {
		t.Errorf("null: got %v err=%v, want nil and no error", list, err)
	}
}

// A CNA score and a third-party score are both present for many CVEs. The
// "Primary" entry is the official one; taking the first would report someone
// else's assessment as NVD's.
func TestNVDMetricListPrefersPrimarySource(t *testing.T) {
	raw := `[
	  {"source":"security@apache.org","type":"Secondary","cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM"}},
	  {"source":"nvd@nist.gov","type":"Primary","cvssData":{"baseScore":10.0,"baseSeverity":"CRITICAL"}}
	]`
	var list nvdMetricList
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatal(err)
	}
	m, ok := list.primary()
	if !ok {
		t.Fatal("no metric selected")
	}
	if m.CVSSData.BaseScore != 10.0 {
		t.Errorf("selected score %v from %q, want the Primary entry's 10.0", m.CVSSData.BaseScore, m.Source)
	}
}

func (m nvdMetric) Severity() string {
	if m.CVSSData.BaseSeverity != "" {
		return m.CVSSData.BaseSeverity
	}
	return m.BaseSeverity
}
