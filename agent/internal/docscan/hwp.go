package docscan

// 한글(HWP 5.0) 본문 텍스트 추출.
//   HWP 5.0 은 OLE 복합 문서(CFB, [MS-CFB]) 안에 FileHeader·BodyText/Section0.. 스트림을 담는다.
//   본문 스트림은 보통 raw deflate 로 압축돼 있고, 레코드(태그·길이) 열로 되어 있다. 글자는 HWPTAG_PARA_TEXT(67) 레코드의 UTF-16LE.
//   암호가 걸렸거나 배포용 문서는 본문이 암호화돼 있어 건너뛴다(오류로 보고).
// 표준 라이브러리만 쓰며, 손상된 파일에서 무한 루프·과다 메모리가 생기지 않게 사슬 길이·크기에 상한을 둔다.

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

var cfbSignature = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

const (
	cfbEndOfChain = 0xFFFFFFFE
	cfbFree       = 0xFFFFFFFF
	cfbNoStream   = 0xFFFFFFFF
	cfbMaxSectors = 1 << 20 // 사슬 길이 상한(손상 파일 무한 루프 방지)
)

type cfbEntry struct {
	name               string
	typ                byte // 1 저장소, 2 스트림, 5 루트
	left, right, child uint32
	start              uint32
	size               uint64
}

type cfbFile struct {
	r          io.ReaderAt
	size       int64
	sectorSize int64
	miniSize   int64
	cutoff     uint64
	fat        []uint32
	miniFAT    []uint32
	entries    []cfbEntry
	miniStream []byte
}

func openCFB(r io.ReaderAt, size int64) (*cfbFile, error) {
	h := make([]byte, 512)
	if _, err := r.ReadAt(h, 0); err != nil {
		return nil, err
	}
	if !bytes.Equal(h[:8], cfbSignature) {
		return nil, errors.New("not a compound file")
	}
	le := binary.LittleEndian
	c := &cfbFile{r: r, size: size}
	shift := le.Uint16(h[0x1E:])
	miniShift := le.Uint16(h[0x20:])
	if shift != 9 && shift != 12 || miniShift != 6 {
		return nil, errors.New("bad sector size")
	}
	c.sectorSize, c.miniSize = 1<<shift, 1<<miniShift
	c.cutoff = uint64(le.Uint32(h[0x38:]))
	nFAT := le.Uint32(h[0x2C:])
	firstDir := le.Uint32(h[0x30:])
	firstMiniFAT := le.Uint32(h[0x3C:])
	nMiniFAT := le.Uint32(h[0x40:])
	firstDIFAT := le.Uint32(h[0x44:])
	nDIFAT := le.Uint32(h[0x48:])
	if nFAT > cfbMaxSectors || nMiniFAT > cfbMaxSectors || nDIFAT > cfbMaxSectors {
		return nil, errors.New("bad header counts")
	}

	// FAT 섹터 목록: 머리말의 109개 + DIFAT 사슬
	fatSectors := make([]uint32, 0, nFAT)
	for i := 0; i < 109 && uint32(len(fatSectors)) < nFAT; i++ {
		fatSectors = append(fatSectors, le.Uint32(h[0x4C+4*i:]))
	}
	perSector := int(c.sectorSize/4) - 1
	for s, n := firstDIFAT, uint32(0); s != cfbEndOfChain && s != cfbFree && n < nDIFAT && uint32(len(fatSectors)) < nFAT; n++ {
		b, err := c.sector(s)
		if err != nil {
			return nil, err
		}
		for i := 0; i < perSector && uint32(len(fatSectors)) < nFAT; i++ {
			fatSectors = append(fatSectors, le.Uint32(b[4*i:]))
		}
		s = le.Uint32(b[4*perSector:])
	}
	for _, s := range fatSectors {
		b, err := c.sector(s)
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(b); i += 4 {
			c.fat = append(c.fat, le.Uint32(b[i:]))
		}
	}

	// 디렉터리
	dir, err := c.chain(firstDir, 0, false)
	if err != nil {
		return nil, err
	}
	for i := 0; i+128 <= len(dir); i += 128 {
		e := dir[i : i+128]
		nl := int(le.Uint16(e[0x40:]))
		if nl > 64 {
			nl = 64
		}
		name := ""
		if nl >= 2 {
			name = utf16le(e[:nl-2])
		}
		c.entries = append(c.entries, cfbEntry{
			name: name, typ: e[0x42],
			left: le.Uint32(e[0x44:]), right: le.Uint32(e[0x48:]), child: le.Uint32(e[0x4C:]),
			start: le.Uint32(e[0x74:]), size: le.Uint64(e[0x78:]) & 0xFFFFFFFF,
		})
	}
	if len(c.entries) == 0 || c.entries[0].typ != 5 {
		return nil, errors.New("no root entry")
	}

	// 작은 스트림용 미니 FAT + 미니 스트림(루트 항목의 사슬)
	if nMiniFAT > 0 {
		mf, err := c.chain(firstMiniFAT, 0, false)
		if err != nil {
			return nil, err
		}
		for i := 0; i+4 <= len(mf); i += 4 {
			c.miniFAT = append(c.miniFAT, le.Uint32(mf[i:]))
		}
		root := c.entries[0]
		if c.miniStream, err = c.chain(root.start, root.size, false); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *cfbFile) sector(s uint32) ([]byte, error) {
	off := (int64(s) + 1) * c.sectorSize
	if s > 0xFFFFFFFA || off >= c.size { // 0xFFFFFFFB 이상은 특수 값. 마지막 섹터는 파일 끝에서 잘려 있을 수 있다
		return nil, fmt.Errorf("sector %d out of range", s)
	}
	b := make([]byte, c.sectorSize)
	n, err := c.r.ReadAt(b, off)
	if err != nil && !(errors.Is(err, io.EOF) && n > 0) {
		return nil, err
	}
	return b, nil
}

// chain 은 시작 섹터부터 사슬을 따라 읽는다. size 가 0 이 아니면 그 크기에서 자른다. mini 면 미니 스트림에서.
func (c *cfbFile) chain(start uint32, size uint64, mini bool) ([]byte, error) {
	var out []byte
	table, unit := c.fat, c.sectorSize
	if mini {
		table, unit = c.miniFAT, c.miniSize
	}
	limit := uint64(MaxText * 4)
	for s, n := start, 0; s != cfbEndOfChain && s != cfbFree; n++ {
		if n > cfbMaxSectors || uint64(len(out)) > limit {
			return nil, errors.New("chain too long")
		}
		if mini {
			off := int64(s) * unit
			if off+unit > int64(len(c.miniStream)) {
				return nil, errors.New("mini sector out of range")
			}
			out = append(out, c.miniStream[off:off+unit]...)
		} else {
			b, err := c.sector(s)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		if int(s) >= len(table) {
			return nil, errors.New("sector not in FAT")
		}
		s = table[s]
		if size > 0 && uint64(len(out)) >= size {
			break
		}
	}
	if size > 0 && uint64(len(out)) > size {
		out = out[:size]
	}
	return out, nil
}

// children 은 저장소 항목의 바로 아래 항목들(레드-블랙 트리: child → left/right 형제)이다.
func (c *cfbFile) children(parent int) []int {
	var out []int
	seen := map[uint32]bool{}
	var walk func(id uint32)
	walk = func(id uint32) {
		if id == cfbNoStream || int(id) >= len(c.entries) || seen[id] || len(seen) > len(c.entries) {
			return
		}
		seen[id] = true
		e := c.entries[id]
		walk(e.left)
		out = append(out, int(id))
		walk(e.right)
	}
	walk(c.entries[parent].child)
	return out
}

func (c *cfbFile) find(parent int, name string) int {
	for _, i := range c.children(parent) {
		if strings.EqualFold(c.entries[i].name, name) {
			return i
		}
	}
	return -1
}

func (c *cfbFile) read(i int) ([]byte, error) {
	e := c.entries[i]
	if e.typ != 2 {
		return nil, errors.New("not a stream")
	}
	if e.size > uint64(MaxText*4) {
		return nil, errors.New("stream too large")
	}
	return c.chain(e.start, e.size, e.size < c.cutoff)
}

// ---------------- HWP ----------------

const hwpTagParaText = 0x10 + 51

func extractHWP(r io.ReaderAt, size int64) (string, error) {
	c, err := openCFB(r, size)
	if err != nil {
		return "", err
	}
	fh := c.find(0, "FileHeader")
	if fh < 0 {
		return "", errors.New("no FileHeader")
	}
	head, err := c.read(fh)
	if err != nil || len(head) < 40 || !strings.HasPrefix(string(head), "HWP Document File") {
		return "", errors.New("not an HWP 5 document")
	}
	props := binary.LittleEndian.Uint32(head[36:])
	compressed := props&1 != 0
	if props&2 != 0 {
		return "", errors.New("password protected")
	}
	if props&4 != 0 {
		return "", errors.New("distribution document (encrypted body)")
	}
	body := c.find(0, "BodyText")
	if body < 0 {
		return "", errors.New("no BodyText")
	}
	// Section0, Section1, ... 번호 순서대로
	type sec struct{ n, idx int }
	var secs []sec
	for _, i := range c.children(body) {
		name := c.entries[i].name
		if strings.HasPrefix(name, "Section") {
			if n, err := strconv.Atoi(strings.TrimPrefix(name, "Section")); err == nil {
				secs = append(secs, sec{n, i})
			}
		}
	}
	sort.Slice(secs, func(a, b int) bool { return secs[a].n < secs[b].n })
	var out strings.Builder
	for _, s := range secs {
		data, err := c.read(s.idx)
		if err != nil {
			continue
		}
		if compressed {
			if data, err = io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(data)), MaxText*4)); err != nil && len(data) == 0 {
				continue
			}
		}
		hwpRecordsText(data, &out)
		if out.Len() >= MaxText {
			break
		}
	}
	if len(secs) == 0 {
		return "", errors.New("no sections")
	}
	return out.String(), nil
}

// hwpRecordsText 는 레코드 열에서 문단 글자 레코드만 골라 글자로 바꾼다.
func hwpRecordsText(data []byte, out *strings.Builder) {
	le := binary.LittleEndian
	for p := 0; p+4 <= len(data) && out.Len() < MaxText; {
		h := le.Uint32(data[p:])
		p += 4
		tag := h & 0x3FF
		size := int(h >> 20)
		if size == 0xFFF {
			if p+4 > len(data) {
				return
			}
			size = int(le.Uint32(data[p:]))
			p += 4
		}
		if size < 0 || p+size > len(data) {
			return
		}
		if tag == hwpTagParaText {
			out.WriteString(hwpParaText(data[p : p+size]))
			out.WriteByte('\n')
		}
		p += size
	}
}

// hwpParaText: 글자 코드 0~31 은 제어 문자. 문자 제어(0,10,13,24~31)는 1칸, 인라인·확장 제어는 8칸(16바이트)을 차지한다.
func hwpParaText(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		if c >= 32 {
			u = append(u, c)
			i += 2
			continue
		}
		switch c {
		case 0, 24, 25, 26, 27, 28, 29, 30, 31:
			i += 2
		case 10, 13:
			u = append(u, ' ')
			i += 2
		default: // 탭(9) 등 인라인 제어, 표·그림 등 확장 제어: 8 WCHAR
			if c == 9 {
				u = append(u, ' ')
			}
			i += 16
		}
	}
	return string(utf16.Decode(u))
}
