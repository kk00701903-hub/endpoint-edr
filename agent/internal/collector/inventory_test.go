package collector

import (
	"testing"
	"time"
)

// SMBIOS 구조를 만든다: 형식 영역(type, len, handle, 나머지) + 문자열들 + 00 00
func smbiosStruct(typ byte, formatted []byte, strs ...string) []byte {
	b := append([]byte{typ, byte(4 + len(formatted)), 0, 0}, formatted...)
	if len(strs) == 0 {
		return append(b, 0, 0)
	}
	for _, s := range strs {
		b = append(append(b, s...), 0)
	}
	return append(b, 0)
}

func TestParseSMBIOS(t *testing.T) {
	bios := smbiosStruct(0, []byte{1, 2, 0, 0}, "LENOVO", "N3HET80W (1.59 )") // 0x04 vendor=1, 0x05 version=2
	sys := smbiosStruct(1, []byte{1, 2, 3, 4}, "LENOVO", "20XWCTO1WW", "ThinkPad", "PF3ABC12")
	empty := smbiosStruct(2, []byte{0, 0})
	end := smbiosStruct(127, nil)
	tables := append(append(append(append([]byte{}, bios...), empty...), sys...), end...)
	raw := append([]byte{0, 3, 4, 0, byte(len(tables)), 0, 0, 0}, tables...)
	got := parseSMBIOS(raw)
	want := smbiosSystem{Manufacturer: "LENOVO", Product: "20XWCTO1WW", Serial: "PF3ABC12", BIOSVersion: "N3HET80W (1.59 )"}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
	// 자리 표시 값은 버림, 잘린 데이터·쓰레기 데이터에서 panic 없음
	sys2 := smbiosStruct(1, []byte{1, 2, 0, 3}, "To Be Filled By O.E.M.", "Default string", "System Serial Number")
	raw2 := append([]byte{0, 3, 4, 0, byte(len(sys2)), 0, 0, 0}, sys2...)
	if g := parseSMBIOS(raw2); g != (smbiosSystem{}) {
		t.Fatalf("placeholders kept: %+v", g)
	}
	for n := 0; n < len(raw); n++ {
		_ = parseSMBIOS(raw[:n])
	}
	_ = parseSMBIOS([]byte{0, 0, 0, 0, 255, 255, 255, 255, 1, 200, 0})
}

func TestKeepSoftware(t *testing.T) {
	cases := []struct {
		name, parent, release string
		sys                   uint64
		keep                  bool
	}{
		{"7-Zip 24.09 (x64)", "", "", 0, true},
		{"", "", "", 0, false},
		{"Microsoft Edge Update", "", "", 1, false},
		{"Security Update for Office (KB5002700)", "", "", 0, false},
		{"Something", "Office16", "", 0, false},
		{"Hotfix thing", "", "Hotfix", 0, false},
		{"Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810 KB2467173", "", "", 0, true},
	}
	for _, c := range cases {
		if got := keepSoftware(c.name, c.sys, c.parent, c.release); got != c.keep {
			t.Errorf("%q: got %v", c.name, got)
		}
	}
}

func TestInstallDateAndProductName(t *testing.T) {
	for in, want := range map[string]string{"20240105": "20240105", "2024-01-05": "20240105", "1/5/2024": "20240105", "20241305": "", "garbage": "", "": ""} {
		if got := normalizeInstallDate(in); got != want {
			t.Errorf("%q → %q want %q", in, got, want)
		}
	}
	if osProductName("Windows 10 Pro", 26100) != "Windows 11 Pro" || osProductName("Windows 10 Pro", 19045) != "Windows 10 Pro" {
		t.Error("product name fix")
	}
}

func TestChangeGate(t *testing.T) {
	g := changeGate{every: time.Hour}
	now := time.Now()
	v := map[string]int{"a": 1}
	if !g.due(v, now) {
		t.Fatal("first must be due")
	}
	g.mark(v, now)
	if g.due(v, now.Add(time.Minute)) {
		t.Fatal("unchanged must wait")
	}
	if !g.due(map[string]int{"a": 2}, now.Add(time.Minute)) {
		t.Fatal("changed must be due")
	}
	if !g.due(v, now.Add(time.Hour)) {
		t.Fatal("heartbeat must be due")
	}
}
