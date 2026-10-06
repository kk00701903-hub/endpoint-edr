package docscan

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/yourorg/endpoint-edr/agent/internal/model"
)

// 시험용 번호(실제 사람 번호가 아니도록 검증 숫자를 계산해 만든다)
func regNo(front, back6 string, gender byte) string {
	d := front + string(gender) + back6[:5]
	w := []int{2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5}
	sum := 0
	for i, x := range w {
		sum += int(d[i]-'0') * x
	}
	return d + fmt.Sprint((11-sum%11)%10)
}

func TestDetector(t *testing.T) {
	plain := regNo("900101", "00000", '1') // 구분자 없는 13자리(검증 숫자 맞음)
	bad := plain[:12] + fmt.Sprint((int(plain[12]-'0')+1)%10)
	text := strings.Join([]string{
		"홍길동 900101-1000000 주소",                        // 하이픈 표기: 날짜만 맞으면 인정(2020년 이후 번호는 검증 숫자 없음)
		"외국인 851231 5123456",                           // 공백 표기, 외국인
		"붙여쓴 " + plain,                                 // 검증 숫자 맞음
		"주문번호 " + bad,                                  // 검증 숫자 틀림 → 제외
		"날짜 틀림 901301-1234567",                         // 13월 → 제외
		"전화 010-1234-5678, 01098765432",                // 2건
		"카드 4111 1111 1111 1111 / 4111-1111-1111-1112", // 1건(Luhn)
		"면허 11-22-333333-44",
		"여권 M12345678 / M123A4567 / XM12345678",
		"기밀 문서, 대외비. 기밀!",
		"연속 900101-1000000,900101-2000000",
	}, "\n")
	pii, kw := NewDetector(AllKinds, []string{"기밀", "대외비", "없는말", "기밀"}).Count(text)
	want := map[string]int{KindRRN: 4, KindFRN: 1, KindPhone: 2, KindCard: 1, KindDriver: 1, KindPassport: 2}
	for k, v := range want {
		if pii[k] != v {
			t.Errorf("%s = %d, want %d (all %v)", k, pii[k], v, pii)
		}
	}
	if kw["기밀"] != 2 || kw["대외비"] != 1 || len(kw) != 2 {
		t.Errorf("keywords %v", kw)
	}
	// 꺼 둔 종류는 세지 않음
	pii, kw = NewDetector([]string{KindRRN}, nil).Count(text)
	if pii[KindPhone] != 0 || pii[KindRRN] != 4 || kw != nil {
		t.Errorf("only rrn: %v %v", pii, kw)
	}
	if p, _ := NewDetector(AllKinds, nil).Count("깨끗한 문서 2024-01-01 금액 1,234,567원"); p != nil {
		t.Errorf("false positive %v", p)
	}
}

func zipFile(t *testing.T, parts map[string]string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range parts {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(body))
	}
	w.Close()
	return buf.Bytes()
}

func TestOfficeAndHWPX(t *testing.T) {
	cases := map[string]map[string]string{
		"docx": {"word/document.xml": `<w:document><w:body><w:p><w:r><w:t>주민</w:t></w:r><w:r><w:t>등록번호 900101-</w:t></w:r><w:r><w:t>1000000</w:t></w:r></w:p><w:p><w:r><w:t>기밀 &amp; 대외비</w:t></w:r></w:p></w:body></w:document>`,
			"word/styles.xml": `<w:t>무시 900101-1000000</w:t>`},
		"xlsx": {"xl/sharedStrings.xml": `<sst><si><t>900101-1000000</t></si><si><t>기밀</t></si></sst>`,
			"xl/worksheets/sheet1.xml": `<worksheet><sheetData><row><c><v>0</v></c><c><v>` + regNo("900101", "00000", '2') + `</v></c></row></sheetData></worksheet>`},
		"pptx": {"ppt/slides/slide1.xml": `<p:sld><a:p><a:r><a:t>900101-1000000 기밀</a:t></a:r></a:p></p:sld>`},
		"hwpx": {"Contents/section0.xml": `<hs:sec><hp:p><hp:run><hp:t>900101-1000000 기밀</hp:t></hp:run></hp:p></hs:sec>`},
	}
	d := NewDetector(AllKinds, []string{"기밀"})
	for ext, parts := range cases {
		b := zipFile(t, parts)
		text, err := ExtractText(ext, bytes.NewReader(b), int64(len(b)))
		if err != nil {
			t.Fatalf("%s: %v", ext, err)
		}
		pii, kw := d.Count(text)
		wantRRN := 1
		if ext == "xlsx" {
			wantRRN = 2 // 공유 문자열 1 + 숫자 셀 1(검증 숫자 맞음)
		}
		if pii[KindRRN] != wantRRN || kw["기밀"] != 1 {
			t.Errorf("%s: pii %v kw %v text %q", ext, pii, kw, text)
		}
	}
	// 손상된 zip 은 오류(패닉 없음)
	if _, err := ExtractText("docx", bytes.NewReader([]byte("PK\x03\x04garbage")), 14); err == nil {
		t.Error("broken zip accepted")
	}
}

// ---------- HWP(OLE 복합 문서) 를 직접 만들어 시험 ----------

func hwpPara(s string) []byte {
	u := utf16.Encode([]rune(s))
	// 앞에 탭(인라인 제어, 8 WCHAR)과 표 같은 확장 제어(11, 8 WCHAR)를 넣어 건너뛰기 시험
	ctrl := func(c uint16) []uint16 { return []uint16{c, 1, 2, 3, 4, 5, 6, c} }
	all := append(append(ctrl(11), ctrl(9)...), u...)
	all = append(all, 13)
	b := make([]byte, 2*len(all))
	for i, c := range all {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	rec := make([]byte, 4)
	binary.LittleEndian.PutUint32(rec, uint32(hwpTagParaText)|uint32(len(b))<<20)
	return append(rec, b...)
}

func buildHWP(t *testing.T, text string, compressed, password bool) []byte {
	body := append([]byte{0x42, 0, 0, 0}, hwpPara(text)...) // 앞에 다른 레코드(태그 0x42, 길이 0) 하나
	if compressed {
		var buf bytes.Buffer
		w, _ := flate.NewWriter(&buf, flate.BestCompression)
		w.Write(body)
		w.Close()
		body = buf.Bytes()
	}
	header := make([]byte, 256)
	copy(header, "HWP Document File")
	var props uint32
	if compressed {
		props |= 1
	}
	if password {
		props |= 2
	}
	binary.LittleEndian.PutUint32(header[36:], props)

	// 미니 스트림: FileHeader(4 미니 섹터) + Section0
	mini := append([]byte{}, header...)
	secStart := uint32(len(mini) / 64)
	mini = append(mini, body...)
	for len(mini)%64 != 0 {
		mini = append(mini, 0)
	}
	nMini := len(mini) / 64
	miniFAT := make([]uint32, 128)
	for i := range miniFAT {
		miniFAT[i] = cfbFree
	}
	chainOf := func(start, n int) {
		for i := start; i < start+n-1; i++ {
			miniFAT[i] = uint32(i + 1)
		}
		miniFAT[start+n-1] = cfbEndOfChain
	}
	chainOf(0, 4)
	chainOf(int(secStart), nMini-int(secStart))

	le := binary.LittleEndian
	sec := func(n int) []byte { return make([]byte, 512*n) }
	// 섹터 0: FAT, 1: 디렉터리, 2: 미니 FAT, 3..: 미니 스트림
	nStreamSectors := (len(mini) + 511) / 512
	fat := sec(1)
	for i := 0; i < 128; i++ {
		le.PutUint32(fat[4*i:], cfbFree)
	}
	le.PutUint32(fat[0:], 0xFFFFFFFD)
	le.PutUint32(fat[4:], cfbEndOfChain)
	le.PutUint32(fat[8:], cfbEndOfChain)
	for i := 0; i < nStreamSectors; i++ {
		next := uint32(3 + i + 1)
		if i == nStreamSectors-1 {
			next = cfbEndOfChain
		}
		le.PutUint32(fat[4*(3+i):], next)
	}
	dir := sec(1)
	entry := func(i int, name string, typ byte, left, right, child, start uint32, size uint64) {
		e := dir[128*i : 128*(i+1)]
		u := utf16.Encode([]rune(name))
		for j, c := range u {
			le.PutUint16(e[2*j:], c)
		}
		le.PutUint16(e[0x40:], uint16(2*len(u)+2))
		e[0x42] = typ
		le.PutUint32(e[0x44:], left)
		le.PutUint32(e[0x48:], right)
		le.PutUint32(e[0x4C:], child)
		le.PutUint32(e[0x74:], start)
		le.PutUint64(e[0x78:], size)
	}
	entry(0, "Root Entry", 5, cfbNoStream, cfbNoStream, 1, 3, uint64(len(mini)))
	entry(1, "FileHeader", 2, cfbNoStream, 2, cfbNoStream, 0, 256)
	entry(2, "BodyText", 1, cfbNoStream, cfbNoStream, 3, 0, 0)
	entry(3, "Section0", 2, cfbNoStream, cfbNoStream, cfbNoStream, secStart, uint64(len(body)))
	mf := sec(1)
	for i, v := range miniFAT {
		le.PutUint32(mf[4*i:], v)
	}
	h := make([]byte, 512)
	copy(h, cfbSignature)
	le.PutUint16(h[0x1A:], 3)
	le.PutUint16(h[0x1C:], 0xFFFE)
	le.PutUint16(h[0x1E:], 9)
	le.PutUint16(h[0x20:], 6)
	le.PutUint32(h[0x2C:], 1)      // FAT 섹터 수
	le.PutUint32(h[0x30:], 1)      // 디렉터리 시작
	le.PutUint32(h[0x38:], 0x1000) // 미니 스트림 기준 크기
	le.PutUint32(h[0x3C:], 2)      // 미니 FAT 시작
	le.PutUint32(h[0x40:], 1)
	le.PutUint32(h[0x44:], cfbEndOfChain)
	for i := 0; i < 109; i++ {
		le.PutUint32(h[0x4C+4*i:], cfbFree)
	}
	le.PutUint32(h[0x4C:], 0)
	stream := sec(nStreamSectors)
	copy(stream, mini)
	return bytes.Join([][]byte{h, fat, dir, mf, stream}, nil)
}

func TestHWP(t *testing.T) {
	d := NewDetector(AllKinds, []string{"대외비"})
	for _, compressed := range []bool{true, false} {
		b := buildHWP(t, "대외비 고객 명단 900101-1000000 010-1234-5678", compressed, false)
		text, err := ExtractText("hwp", bytes.NewReader(b), int64(len(b)))
		if err != nil {
			t.Fatalf("compressed=%v: %v", compressed, err)
		}
		pii, kw := d.Count(text)
		if pii[KindRRN] != 1 || pii[KindPhone] != 1 || kw["대외비"] != 1 || strings.ContainsRune(text, 11) {
			t.Errorf("compressed=%v: %v %v %q", compressed, pii, kw, text)
		}
	}
	b := buildHWP(t, "비밀", true, true)
	if _, err := ExtractText("hwp", bytes.NewReader(b), int64(len(b))); err == nil || !strings.Contains(err.Error(), "password") {
		t.Errorf("password hwp: %v", err)
	}
	// 잘린·망가진 파일: 오류만, 패닉 없음
	full := buildHWP(t, "x", true, false)
	for n := 0; n < len(full); n += 97 {
		_, _ = ExtractText("hwp", bytes.NewReader(full[:n]), int64(n))
	}
	garbage := append(append([]byte{}, cfbSignature...), bytes.Repeat([]byte{0xFF}, 2000)...)
	if _, err := ExtractText("hwp", bytes.NewReader(garbage), int64(len(garbage))); err == nil {
		t.Error("garbage hwp accepted")
	}
}

// ---------- PDF ----------

func buildPDF(text string) []byte {
	content := fmt.Sprintf("BT /F1 12 Tf 72 712 Td (%s) Tj ET", text)
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offs := make([]int, len(objs))
	for i, o := range objs {
		offs[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	x := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offs {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, x)
	return b.Bytes()
}

func TestPDFAndBinary(t *testing.T) {
	d := NewDetector(AllKinds, []string{"confidential"})
	p := buildPDF("CONFIDENTIAL RRN 900101-1000000")
	text, err := ExtractText("pdf", bytes.NewReader(p), int64(len(p)))
	if err != nil {
		t.Fatal(err)
	}
	if pii, kw := d.Count(text); pii[KindRRN] != 1 || kw["confidential"] != 1 {
		t.Errorf("pdf %v %v %q", pii, kw, text)
	}
	if _, err := ExtractText("pdf", bytes.NewReader([]byte("%PDF-1.4 broken")), 15); err == nil {
		t.Error("broken pdf accepted")
	}
	// 옛 Office: ASCII + UTF-16LE 글자열
	u := utf16.Encode([]rune("고객 900101-2000000"))
	ub := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(ub[2*i:], c)
	}
	bin := append(append([]byte{0, 1, 2, 0xFF}, []byte("phone 010-2222-3333")...), append([]byte{0, 0, 9}, ub...)...)
	text, _ = ExtractText("xls", bytes.NewReader(bin), int64(len(bin)))
	if pii, _ := d.Count(text); pii[KindRRN] != 1 || pii[KindPhone] != 1 {
		t.Errorf("binary %v %q", pii, text)
	}
	// UTF-16 텍스트 파일
	txt := append([]byte{0xFF, 0xFE}, ub...)
	text, _ = ExtractText("txt", bytes.NewReader(txt), int64(len(txt)))
	if pii, _ := d.Count(text); pii[KindRRN] != 1 {
		t.Errorf("utf16 txt %q", text)
	}
}

// ---------- 폴더 검사 전체 흐름 ----------

func TestRun(t *testing.T) {
	root := t.TempDir()
	users := filepath.Join(root, "Users")
	docs := filepath.Join(users, "kim", "Documents")
	os.MkdirAll(filepath.Join(docs, "sub"), 0o755)
	os.MkdirAll(filepath.Join(users, "kim", "AppData", "Local"), 0o755)
	os.MkdirAll(filepath.Join(users, "Default", "Documents"), 0o755)
	write := func(p string, b []byte, age time.Duration) {
		os.WriteFile(p, b, 0o644)
		mt := time.Now().Add(-age)
		os.Chtimes(p, mt, mt)
	}
	write(filepath.Join(docs, "고객명단.txt"), []byte("900101-1000000\n900101-2000000"), time.Hour)
	write(filepath.Join(docs, "sub", "보고서.docx"), zipFile(t, map[string]string{"word/document.xml": "<w:t>대외비</w:t>"}), time.Hour)
	write(filepath.Join(docs, "옛날.txt"), []byte("평범한 내용"), 4*365*24*time.Hour)
	write(filepath.Join(docs, "평범.txt"), []byte("평범한 내용"), time.Hour)
	write(filepath.Join(docs, "그림.png"), []byte("900101-1000000"), time.Hour)                            // 확장자 아님
	write(filepath.Join(docs, "큰파일.txt"), bytes.Repeat([]byte("a"), 2<<20), time.Hour)                   // 크기 상한
	write(filepath.Join(users, "kim", "AppData", "Local", "x.txt"), []byte("900101-1000000"), time.Hour) // 건너뛸 폴더
	write(filepath.Join(users, "Default", "Documents", "d.txt"), []byte("900101-1000000"), time.Hour)    // 기본 사용자
	p := Policy{Enabled: true, Folders: []string{"Documents", "../etc"}, Extensions: []string{"txt", ".DOCX"},
		Detect: AllKinds, Keywords: []string{"대외비"}, StaleDays: 1095, MaxFileMB: 1, RequestID: 7}
	roots := Roots(p, users)
	if len(roots) != 1 || roots[0] != docs {
		t.Fatalf("roots %v", roots)
	}
	var batches []*model.DocScanBatch
	lim := DefaultLimits()
	lim.BatchSize = 2
	lim.PausePerFile = 0
	if !Run(p, roots, "request", lim, func(b *model.DocScanBatch) bool { c := *b; batches = append(batches, &c); return true }, make(chan struct{})) {
		t.Fatal("complete run returned false")
	}
	if len(batches) < 2 || !batches[len(batches)-1].Final || batches[0].Final {
		t.Fatalf("batches %d", len(batches))
	}
	got := map[string]model.DocFinding{}
	scanned, skipped := 0, 0
	for _, b := range batches {
		if b.ScanID != batches[0].ScanID || b.RequestID != 7 || b.Trigger != "request" {
			t.Errorf("batch header %+v", b)
		}
		scanned += b.FilesScanned
		skipped += b.FilesSkipped
		for _, f := range b.Findings {
			got[filepath.Base(f.Path)] = f
		}
	}
	if len(got) != 3 || got["고객명단.txt"].PII[KindRRN] != 2 || got["보고서.docx"].Keywords["대외비"] != 1 || !got["옛날.txt"].Stale || got["옛날.txt"].PII != nil {
		t.Errorf("findings %+v", got)
	}
	if scanned != 4 || skipped != 1 {
		t.Errorf("scanned %d skipped %d", scanned, skipped)
	}
	// 멈추라고 하면 최종 배치를 보내지 않는다(서버가 기존 결과를 지우지 않게)
	stop := make(chan struct{})
	close(stop)
	batches = nil
	if Run(p, roots, "schedule", lim, func(b *model.DocScanBatch) bool { c := *b; batches = append(batches, &c); return true }, stop) {
		t.Error("stopped run returned true")
	}
	for _, b := range batches {
		if b.Final {
			t.Errorf("stopped run sent final %+v", b)
		}
	}
	// 전송이 막히면(emit false) 그 자리에서 멈추고 최종 배치 없음
	batches = nil
	if Run(p, roots, "schedule", lim, func(b *model.DocScanBatch) bool { c := *b; batches = append(batches, &c); return false }, make(chan struct{})) {
		t.Error("emit-failed run returned true")
	}
	if len(batches) != 1 || batches[0].Final {
		t.Errorf("emit-failed run %+v", batches)
	}
}

func TestRunnerSchedule(t *testing.T) {
	dir := t.TempDir()
	r := NewRunner(dir)
	now := time.Now()
	p, err := ParsePolicy([]byte(`{"doc_scan":{"enabled":true,"interval_hours":168,"folders":["Documents"],"extensions":["txt"],"detect":["rrn"],"request_id":3}}`))
	if err != nil || !p.Enabled || p.RequestID != 3 {
		t.Fatalf("parse %+v %v", p, err)
	}
	if tr, ok := r.Due(p, now); !ok || tr != "request" {
		t.Fatalf("request due: %v %v", tr, ok)
	}
	out := make(chan *model.DocScanBatch, 4)
	r.Start(p, nil, "request", DefaultLimits(), out, make(chan struct{}))
	if b := <-out; !b.Final || b.RequestID != 3 {
		t.Fatalf("batch %+v", b)
	}
	for r.Running() {
		time.Sleep(5 * time.Millisecond)
	}
	// 중간에 멈춘 검사는 기록하지 않는다 → 같은 요청이 다시 차례가 된다
	r3 := NewRunner(t.TempDir())
	stop := make(chan struct{})
	close(stop)
	r3.Start(p, []string{dir}, "request", DefaultLimits(), make(chan *model.DocScanBatch), stop)
	for r3.Running() {
		time.Sleep(5 * time.Millisecond)
	}
	if tr, ok := r3.Due(p, now); !ok || tr != "request" {
		t.Errorf("aborted request should stay due: %v %v", tr, ok)
	}
	r2 := NewRunner(dir) // 상태 파일에서 다시 읽음
	if _, ok := r2.Due(p, now.Add(time.Hour)); ok {
		t.Error("same request / within interval should not be due")
	}
	if tr, ok := r2.Due(p, now.Add(169*time.Hour)); !ok || tr != "schedule" {
		t.Error("interval elapsed should be due")
	}
	p.Enabled = false
	if _, ok := r2.Due(p, now.Add(999*time.Hour)); ok {
		t.Error("disabled policy due")
	}
}
