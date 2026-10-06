// 수집 서버 단위 시험(DB 없이 도는 것만). 종단 시험은 tests/integration.
package main

import (
	"testing"

	"github.com/yourorg/endpoint-edr/services/internal/contract"
)

func TestStripNUL(t *testing.T) {
	for in, want := range map[string]string{
		`{"a":"x\u0000"}`:         `{"a":"x"}`,
		`{"a":"c:\\u0000dir"}`:    `{"a":"c:\\u0000dir"}`,
		`{"a":"c:\\\u0000"}`:      `{"a":"c:\\"}`,
		`{"a":"plain"}`:           `{"a":"plain"}`,
		`{"a":"\u0000\u0000\"q"}`: `{"a":"\"q"}`,
	} {
		if got := stripNUL([]byte(in)); got != want {
			t.Errorf("%s → %s want %s", in, got, want)
		}
	}
}

func TestValidDocScan(t *testing.T) {
	ok := &contract.DocScanBatch{ScanID: "0123456789abcdef", Trigger: "schedule", Findings: []contract.DocFinding{
		{Path: `C:\Users\kim\Documents\a.xlsx`, PII: map[string]int{"rrn": 3}, Keywords: map[string]int{"대외비": 1}},
	}}
	if msg := validDocScan(ok); msg != "" {
		t.Fatalf("valid batch rejected: %s", msg)
	}
	bad := []func(b *contract.DocScanBatch){
		func(b *contract.DocScanBatch) { b.ScanID = "XYZ" },
		func(b *contract.DocScanBatch) { b.Trigger = "push" },
		func(b *contract.DocScanBatch) { b.FilesScanned = -1 },
		func(b *contract.DocScanBatch) { b.Findings[0].Path = "" },
		func(b *contract.DocScanBatch) { b.Findings[0].PII = map[string]int{"rrn_value": 1} },
		func(b *contract.DocScanBatch) { b.Findings = make([]contract.DocFinding, maxDocFindings+1) },
	}
	for i, mut := range bad {
		b := *ok
		b.Findings = append([]contract.DocFinding(nil), ok.Findings...)
		mut(&b)
		if validDocScan(&b) == "" {
			t.Errorf("case %d accepted", i)
		}
	}
}
