package docscan

// 문서에서 검사할 텍스트를 뽑는다. 외부 프로그램을 실행하지 않고 파일 바이트만 읽는다.
//   텍스트(txt·csv 등)        : UTF-8 / UTF-16(BOM)
//   Office Open XML(docx 등)  : zip 안의 본문 XML
//   한글 hwpx                 : zip 안의 Contents/section*.xml
//   한글 hwp(5.0)             : OLE 복합 문서 → BodyText/Section* (압축 해제 후 문단 글자 레코드)
//   PDF                       : github.com/ledongthuc/pdf 로 쪽마다 글자 추출
//   옛 Office(doc·xls·ppt)    : 바이트에서 글자열(ASCII·UTF-16) 뽑기 — 숫자 형태 개인정보 위주로 찾는다
// 어떤 형식이든 오류·손상 파일은 오류로 돌려주고(panic 없음), 압축 폭탄을 막기 위해 풀어낸 크기에 상한을 둔다.

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/ledongthuc/pdf"
)

// MaxText 는 파일 하나에서 검사할 글자 수 상한(바이트)이다.
// 에이전트 메모리 상한(150MB)을 넘지 않도록 작게 잡는다(텍스트 + 소문자 사본 ≈ 16MB).
const MaxText = 8 << 20

var ErrUnsupported = errors.New("unsupported format")

// Extensions 는 기본 검사 확장자다(서버 정책이 바꿀 수 있다).
var Extensions = []string{"txt", "csv", "log", "docx", "xlsx", "pptx", "hwp", "hwpx", "pdf", "doc", "xls", "ppt"}

// ExtractText 는 확장자(ext, 소문자·점 없음)에 맞게 텍스트를 뽑는다. r 은 파일 전체, size 는 크기.
func ExtractText(ext string, r io.ReaderAt, size int64) (text string, err error) {
	defer func() {
		if p := recover(); p != nil { // 라이브러리·파서의 예기치 못한 panic 도 파일 하나의 오류로만 처리
			text, err = "", fmt.Errorf("parse panic: %v", p)
		}
	}()
	switch ext {
	case "txt", "csv", "log", "tsv", "md":
		b, err := io.ReadAll(io.NewSectionReader(r, 0, min64(size, MaxText)))
		if err != nil {
			return "", err
		}
		return decodeText(b), nil
	case "docx", "xlsx", "pptx", "hwpx":
		return extractZipXML(ext, r, size)
	case "hwp":
		return extractHWP(r, size)
	case "pdf":
		return extractPDF(r, size)
	case "doc", "xls", "ppt":
		b, err := io.ReadAll(io.NewSectionReader(r, 0, min64(size, MaxText)))
		if err != nil {
			return "", err
		}
		return binaryStrings(b), nil
	}
	return "", ErrUnsupported
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// decodeText 는 BOM 으로 UTF-16 을 알아보고, 아니면 UTF-8 로 본다(CP949 한글은 깨지지만 숫자 형태 개인정보는 그대로 찾힌다).
func decodeText(b []byte) string {
	switch {
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		return utf16le(b[2:])
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		u := make([]uint16, len(b[2:])/2)
		for i := range u {
			u[i] = uint16(b[2+2*i])<<8 | uint16(b[3+2*i])
		}
		return string(utf16.Decode(u))
	case len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF:
		return string(b[3:])
	}
	return string(b)
}

func utf16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

// ---------------- zip + XML (docx·xlsx·pptx·hwpx) ----------------

func zipParts(ext, name string) bool {
	n := strings.ToLower(name)
	switch ext {
	case "docx":
		return n == "word/document.xml" || strings.HasPrefix(n, "word/header") || strings.HasPrefix(n, "word/footer") ||
			n == "word/footnotes.xml" || n == "word/endnotes.xml" || n == "word/comments.xml"
	case "xlsx":
		return n == "xl/sharedstrings.xml" || (strings.HasPrefix(n, "xl/worksheets/sheet") && strings.HasSuffix(n, ".xml"))
	case "pptx":
		return (strings.HasPrefix(n, "ppt/slides/slide") || strings.HasPrefix(n, "ppt/notesslides/notesslide")) && strings.HasSuffix(n, ".xml")
	case "hwpx":
		return strings.HasPrefix(n, "contents/section") && strings.HasSuffix(n, ".xml")
	}
	return false
}

func extractZipXML(ext string, r io.ReaderAt, size int64) (string, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return "", err
	}
	files := make([]*zip.File, 0, 8)
	for _, f := range zr.File {
		if zipParts(ext, f.Name) {
			files = append(files, f)
		}
	}
	sort.Slice(files, func(i, j int) bool { return naturalLess(files[i].Name, files[j].Name) })
	var out strings.Builder
	budget := int64(MaxText * 3) // XML 은 태그가 많아 풀어낸 바이트 상한을 텍스트 상한의 3배로
	for _, f := range files {
		if budget <= 0 {
			break
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, budget))
		rc.Close()
		if err != nil && len(b) == 0 {
			continue
		}
		budget -= int64(len(b))
		out.WriteString(xmlText(b))
		out.WriteByte('\n')
		if out.Len() >= MaxText {
			break
		}
	}
	if len(files) == 0 {
		return "", errors.New("no text parts")
	}
	return out.String(), nil
}

// naturalLess: sheet2.xml 이 sheet10.xml 보다 앞에 오도록
func naturalLess(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// xmlText 는 태그를 빼고 글자만 남긴다. 태그 자리는 공백 하나(셀·문단 경계에서 숫자가 붙지 않게).
// 같은 단어가 서식 때문에 여러 태그(<w:t>주민</w:t><w:t>등록</w:t>)로 나뉘는 경우를 위해 "글자 사이 태그"는 붙여 쓴다.
func xmlText(b []byte) string {
	var out strings.Builder
	out.Grow(len(b) / 3)
	inTag := false
	var tag strings.Builder
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inTag {
			if c == '>' {
				inTag = false
				t := tag.String()
				// 문단·행·셀·줄바꿈 경계는 공백, 글자 조각(w:t, a:t, hp:t)의 경계는 그대로 붙인다
				if isBreakTag(t) {
					out.WriteByte(' ')
				}
				tag.Reset()
			} else if tag.Len() < 32 {
				tag.WriteByte(c)
			}
			continue
		}
		switch c {
		case '<':
			inTag = true
		case '&':
			if j := bytes.IndexByte(b[i:min(i+10, len(b))], ';'); j > 0 {
				out.WriteString(entity(string(b[i+1 : i+j])))
				i += j
			} else {
				out.WriteByte(c)
			}
		default:
			out.WriteByte(c)
		}
		if out.Len() >= MaxText {
			break
		}
	}
	return out.String()
}

func isBreakTag(t string) bool {
	t = strings.TrimPrefix(t, "/")
	if i := strings.IndexAny(t, " \t\r\n/"); i >= 0 {
		t = t[:i]
	}
	if j := strings.IndexByte(t, ':'); j >= 0 {
		t = t[j+1:]
	}
	switch t {
	case "p", "br", "tab", "tc", "c", "row", "si", "cr", "lineBreak", "v", "is", "tr", "sp":
		return true
	}
	return false
}

func entity(e string) string {
	switch e {
	case "amp":
		return "&"
	case "lt":
		return "<"
	case "gt":
		return ">"
	case "quot":
		return `"`
	case "apos":
		return "'"
	}
	if strings.HasPrefix(e, "#") {
		var n int
		var err error
		if strings.HasPrefix(e, "#x") {
			_, err = fmt.Sscanf(e[2:], "%x", &n)
		} else {
			_, err = fmt.Sscanf(e[1:], "%d", &n)
		}
		if err == nil && n > 0 && n < 0x110000 {
			return string(rune(n))
		}
	}
	return " "
}

// ---------------- PDF ----------------

const maxPDFPages = 300

func extractPDF(r io.ReaderAt, size int64) (string, error) {
	pr, err := pdf.NewReader(r, size)
	if err != nil {
		return "", err // 암호가 걸린 PDF 도 여기서 오류
	}
	var out strings.Builder
	n := pr.NumPage()
	if n > maxPDFPages {
		n = maxPDFPages
	}
	for i := 1; i <= n && out.Len() < MaxText; i++ {
		p := pr.Page(i)
		if p.V.IsNull() {
			continue
		}
		t, err := p.GetPlainText(nil) // 글꼴 이름(F1 등)은 쪽마다 다른 글꼴일 수 있어 쪽마다 새로 읽는다
		if err != nil {
			continue
		}
		out.WriteString(t)
		out.WriteByte('\n')
	}
	return out.String(), nil
}

// ---------------- 옛 Office(바이너리) ----------------

// binaryStrings 는 바이트에서 4글자 이상 이어진 글자열을 ASCII 와 UTF-16LE 두 방식으로 뽑는다(유닉스 strings 와 같은 방식).
func binaryStrings(b []byte) string {
	var out strings.Builder
	// ASCII
	start := -1
	for i := 0; i <= len(b); i++ {
		printable := i < len(b) && b[i] >= 0x20 && b[i] < 0x7F
		if printable && start < 0 {
			start = i
		}
		if !printable && start >= 0 {
			if i-start >= 4 {
				out.Write(b[start:i])
				out.WriteByte('\n')
			}
			start = -1
		}
	}
	// UTF-16LE (한글 포함): 짝수·홀수 위치 두 번
	for off := 0; off < 2; off++ {
		var run []uint16
		flush := func() {
			if len(run) >= 2 {
				out.WriteString(string(utf16.Decode(run)))
				out.WriteByte('\n')
			}
			run = run[:0]
		}
		for i := off; i+1 < len(b); i += 2 {
			c := uint16(b[i]) | uint16(b[i+1])<<8
			if (c >= 0x20 && c < 0x7F) || (c >= 0xAC00 && c <= 0xD7A3) || (c >= 0x3131 && c <= 0x318E) {
				run = append(run, c)
			} else {
				flush()
			}
			if out.Len() >= MaxText {
				break
			}
		}
		flush()
	}
	s := out.String()
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, " ")
	}
	return s
}

// Ext 는 경로의 확장자(소문자, 점 없음)다.
func Ext(p string) string {
	return strings.TrimPrefix(strings.ToLower(path.Ext(strings.ReplaceAll(p, `\`, "/"))), ".")
}
