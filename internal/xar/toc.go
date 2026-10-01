package xar

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The TOC is parsed by a small streaming tokenizer rather than encoding/xml,
// whose Decoder materialises every attribute, name and namespace of a start
// tag before the caller sees it. Here no markup is stored except the names
// of the open elements (at most maxTOCDepth * maxTOCTagName bytes), and only
// the text and the one attribute of the few elements that are used (at most
// maxTOCField and maxTOCTag bytes). Every tag is bounded by maxTOCTag bytes.
// So beyond the entries themselves memory is a small constant, and time is
// linear in the TOC size, which is already capped.
//
// It accepts the XML subset xar writes: a prolog, elements, attributes,
// character and entity references, CDATA sections, comments and processing
// instructions. A DOCTYPE or other declaration is rejected.

// tocKind identifies the elements the parser uses. Every other element is
// kOther, and so is everything inside one, so it needs no further state.
type tocKind uint8

const (
	kOther tocKind = iota
	kRoot
	kTOC
	kFile
	kName
	kType
	kLink
	kData
	kOffset
	kLength
	kSize
	kEncoding
	kSig
	kKeyInfo
	kX509Data
	kCert
)

// childKind gives the kind of an element with the given local name inside
// one of kind parent.
func childKind(parent tocKind, local []byte) tocKind {
	switch parent {
	case kRoot:
		if string(local) == "toc" {
			return kTOC
		}
	case kTOC:
		switch string(local) {
		case "file":
			return kFile
		case "signature", "x-signature":
			return kSig
		}
	case kFile:
		switch string(local) {
		case "file":
			return kFile
		case "name":
			return kName
		case "type":
			return kType
		case "link":
			return kLink
		case "data":
			return kData
		}
	case kData:
		switch string(local) {
		case "offset":
			return kOffset
		case "length":
			return kLength
		case "size":
			return kSize
		case "encoding":
			return kEncoding
		}
	case kSig:
		if string(local) == "KeyInfo" {
			return kKeyInfo
		}
	case kKeyInfo:
		if string(local) == "X509Data" {
			return kX509Data
		}
	case kX509Data:
		if string(local) == "X509Certificate" {
			return kCert
		}
	}
	return kOther
}

// kept reports whether an element's text is used. Kept elements never
// contain other kept elements, so one text buffer serves them all.
func (k tocKind) kept() bool {
	switch k {
	case kName, kType, kLink, kOffset, kLength, kSize, kCert:
		return true
	}
	return false
}

type tocFrame struct {
	kind  tocKind
	entry int // innermost enclosing file entry, or -1
	sig   int // enclosing signature (0 signature, 1 x-signature), or -1
	name  int // offset of its raw name in tocParser.open
}

type tocParser struct {
	a     *Archive
	r     *bufio.Reader
	stack []tocFrame
	open  []byte // raw names of the open elements, concatenated
	tag   int    // bytes left for the current tag
	text  []byte // text of the open kept element
	name  []byte // scratch: last name read
	attr  []byte // scratch: wanted attribute value

	parent []int    // per entry: parent entry, or -1
	names  []string // per entry
	styles [2]string
	certs  [2][]string
}

func (p *tocParser) byte() (byte, error) {
	c, err := p.r.ReadByte()
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return c, err
}

// tagByte reads a byte of a tag, charging it to the tag budget.
func (p *tocParser) tagByte() (byte, error) {
	if p.tag--; p.tag < 0 {
		return 0, errors.New("tag too long")
	}
	return p.byte()
}

func (p *tocParser) peekLF() bool {
	b, err := p.r.Peek(1)
	return err == nil && b[0] == '\n'
}

// skipUntil discards input up to and including term, which is "?>" or
// "-->": terminators that only overlap themselves by repeating term[0].
func (p *tocParser) skipUntil(term string) error {
	m := 0
	for m < len(term) {
		c, err := p.byte()
		if err != nil {
			return err
		}
		switch {
		case c == term[m]:
			m++
		case c == term[0] && m > 0 && term[m-1] == term[0]:
			// e.g. "--->": still a full prefix match.
		case c == term[0]:
			m = 1
		default:
			m = 0
		}
	}
	return nil
}

func isNameByte(c byte) bool {
	return c >= 0x80 || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '_' || c == ':' || c == '.' || c == '-'
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// readName reads an element or attribute name into p.name and returns the
// first byte after it. Names are short in any real TOC; long ones are
// rejected before they cost anything.
func (p *tocParser) readName() (byte, error) {
	p.name = p.name[:0]
	for {
		c, err := p.tagByte()
		if err != nil {
			return 0, err
		}
		if !isNameByte(c) {
			if len(p.name) == 0 {
				return 0, fmt.Errorf("invalid character %q in markup", c)
			}
			return c, nil
		}
		if len(p.name) >= maxTOCTagName {
			return 0, errors.New("element or attribute name too long")
		}
		p.name = append(p.name, c)
	}
}

// skipSpace returns the first non-space byte from c on.
func (p *tocParser) skipSpace(c byte) (byte, error) {
	var err error
	for err == nil && isSpace(c) {
		c, err = p.tagByte()
	}
	return c, err
}

// localName strips a namespace prefix, as encoding/xml does.
func localName(b []byte) []byte {
	if i := bytes.IndexByte(b, ':'); i >= 0 {
		return b[i+1:]
	}
	return b
}

func isXMLChar(r rune) bool {
	return r == 0x09 || r == 0x0A || r == 0x0D || r >= 0x20 && r <= 0xD7FF ||
		r >= 0xE000 && r <= 0xFFFD || r >= 0x10000 && r <= 0x10FFFF
}

// appendText appends the character data starting with c to buf, decoding a
// reference if c is '&' and normalising line ends as encoding/xml does.
// next supplies further input.
func (p *tocParser) appendText(buf []byte, c byte, next func() (byte, error)) ([]byte, error) {
	switch c {
	case '\r':
		if p.peekLF() {
			next()
		}
		return append(buf, '\n'), nil
	case '&':
	default:
		return append(buf, c), nil
	}
	var ref [12]byte
	n := 0
	for {
		c, err := next()
		if err != nil {
			return buf, err
		}
		if c == ';' {
			break
		}
		if n == len(ref) {
			return buf, errors.New("invalid entity reference")
		}
		ref[n] = c
		n++
	}
	s := string(ref[:n])
	switch s {
	case "amp":
		return append(buf, '&'), nil
	case "lt":
		return append(buf, '<'), nil
	case "gt":
		return append(buf, '>'), nil
	case "apos":
		return append(buf, '\''), nil
	case "quot":
		return append(buf, '"'), nil
	}
	if num, ok := strings.CutPrefix(s, "#"); ok {
		base := 10
		if hex, ok := strings.CutPrefix(num, "x"); ok {
			num, base = hex, 16
		}
		if v, err := strconv.ParseUint(num, base, 32); err == nil && isXMLChar(rune(v)) {
			return utf8.AppendRune(buf, rune(v)), nil
		}
	}
	return buf, fmt.Errorf("invalid entity reference &%s;", s)
}

func (p *tocParser) keptTop() bool {
	n := len(p.stack)
	return n > 0 && p.stack[n-1].kind.kept()
}

func (p *tocParser) checkText() error {
	if len(p.text) > maxTOCField {
		return errors.New("element text too long")
	}
	return nil
}

// parseTOC streams the TOC XML, collecting file entries (<toc><file>,
// nested) and signing certificates (<toc><signature> and
// <toc><x-signature>) without materialising the document. The text of a
// kept element is its own character data, excluding that of any child
// elements, as with xml.Unmarshal into a string field.
func (a *Archive) parseTOC(r io.Reader) error {
	p := &tocParser{a: a, r: bufio.NewReaderSize(r, 32<<10)}
	for done := false; !done; {
		c, err := p.byte()
		if err != nil {
			return err
		}
		if c == '<' {
			done, err = p.markup()
		} else if p.keptTop() {
			// Other text is skipped without decoding or storing it.
			if p.text, err = p.appendText(p.text, c, p.byte); err == nil {
				err = p.checkText()
			}
		}
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return err
		}
	}

	// Parents always precede their children, so one pass resolves paths.
	// Each path repeats its parent's, so bound their total as well.
	total := 0
	for i := range a.Entries {
		dir := ""
		if p.parent[i] >= 0 {
			dir = a.Entries[p.parent[i]].Path
		}
		if total += len(dir) + 1 + len(p.names[i]); total > maxTOCPaths {
			return errors.New("entry paths too long")
		}
		a.Entries[i].Path = path.Join(dir, p.names[i])
	}
	for _, s := range p.styles {
		if a.SigStyle == "" {
			a.SigStyle = s
		}
	}
	for _, c := range append(p.certs[0], p.certs[1]...) {
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c), ""))
		if err != nil {
			continue
		}
		if cert, err := x509.ParseCertificate(der); err == nil {
			a.Certs = append(a.Certs, cert)
		}
	}
	return nil
}

// markup handles the markup after a '<', reporting whether it ended the
// root element.
func (p *tocParser) markup() (bool, error) {
	c, err := p.byte()
	if err != nil {
		return false, err
	}
	switch c {
	case '?':
		return false, p.skipUntil("?>")
	case '!':
		var head [7]byte
		if _, err := io.ReadFull(p.r, head[:2]); err != nil {
			return false, err
		}
		if string(head[:2]) == "--" {
			return false, p.skipUntil("-->")
		}
		if _, err := io.ReadFull(p.r, head[2:]); err != nil {
			return false, err
		}
		if string(head[:]) == "[CDATA[" {
			return false, p.cdata()
		}
		return false, errors.New("unsupported markup declaration")
	case '/':
		return p.endTag()
	}
	if err := p.r.UnreadByte(); err != nil {
		return false, err
	}
	return p.startTag()
}

// cdata reads a CDATA section through "]]>", adding it literally (save for
// line ends) to any kept text.
func (p *tocParser) cdata() error {
	keep := p.keptTop()
	brackets := 0 // run of ']' that may start the terminator
	for {
		c, err := p.byte()
		if err != nil {
			return err
		}
		if c == ']' {
			brackets++
			continue
		}
		end := c == '>' && brackets >= 2
		if end {
			brackets -= 2
		}
		if keep {
			for ; brackets > 0; brackets-- {
				p.text = append(p.text, ']')
				if err := p.checkText(); err != nil {
					return err
				}
			}
			if !end {
				if c == '\r' {
					if p.peekLF() {
						p.byte()
					}
					c = '\n'
				}
				p.text = append(p.text, c)
				if err := p.checkText(); err != nil {
					return err
				}
			}
		}
		if end {
			return nil
		}
		brackets = 0
	}
}

func (p *tocParser) endTag() (bool, error) {
	n := len(p.stack)
	if n == 0 {
		return false, errors.New("unexpected end element")
	}
	p.tag = maxTOCTag
	c, err := p.readName()
	if err != nil {
		return false, err
	}
	if c, err = p.skipSpace(c); err != nil {
		return false, err
	}
	if c != '>' {
		return false, errors.New("malformed end tag")
	}
	if open := p.open[p.stack[n-1].name:]; !bytes.Equal(open, p.name) {
		return false, fmt.Errorf("element <%s> closed by </%s>", open, p.name)
	}
	return p.end()
}

// startTag parses a start tag whose name is pending. Of its attributes only
// the style of a signature or encoding element is kept; the rest are read
// and discarded.
func (p *tocParser) startTag() (bool, error) {
	if len(p.stack) >= maxTOCDepth {
		return false, errors.New("nested too deeply")
	}
	p.tag = maxTOCTag
	c, err := p.readName()
	if err != nil {
		return false, err
	}
	fr := tocFrame{kind: kRoot, entry: -1, sig: -1, name: len(p.open)}
	if n := len(p.stack); n > 0 {
		top := p.stack[n-1]
		fr.kind = childKind(top.kind, localName(p.name))
		fr.entry, fr.sig = top.entry, top.sig
	}
	p.open = append(p.open, p.name...)
	wantStyle := fr.kind == kSig || fr.kind == kEncoding
	style, found := "", false
	for {
		if c, err = p.skipSpace(c); err != nil {
			return false, err
		}
		if c == '>' || c == '/' {
			break
		}
		if err = p.r.UnreadByte(); err != nil {
			return false, err
		}
		p.tag++
		if c, err = p.readName(); err != nil {
			return false, err
		}
		keep := wantStyle && !found && string(localName(p.name)) == "style"
		if c, err = p.skipSpace(c); err != nil {
			return false, err
		}
		if c != '=' {
			return false, errors.New("attribute without value")
		}
		if c, err = p.tagByte(); err != nil {
			return false, err
		}
		q, err := p.skipSpace(c)
		if err != nil {
			return false, err
		}
		if q != '"' && q != '\'' {
			return false, errors.New("unquoted attribute value")
		}
		p.attr = p.attr[:0]
		for {
			if c, err = p.tagByte(); err != nil {
				return false, err
			}
			if c == q {
				break
			}
			if c == '<' {
				return false, errors.New("'<' in attribute value")
			}
			if keep { // the tag budget bounds the value too
				if p.attr, err = p.appendText(p.attr, c, p.tagByte); err != nil {
					return false, err
				}
			}
		}
		if keep {
			style, found = string(p.attr), true
		}
		if c, err = p.tagByte(); err != nil {
			return false, err
		}
		if !isSpace(c) && c != '>' && c != '/' {
			return false, errors.New("malformed start tag")
		}
	}
	empty := c == '/'
	if empty {
		if c, err = p.tagByte(); err != nil {
			return false, err
		}
		if c != '>' {
			return false, errors.New("malformed start tag")
		}
	}

	a := p.a
	switch fr.kind {
	case kFile:
		if len(a.Entries) >= maxTOCEntries {
			return false, errors.New("too many entries")
		}
		a.Entries = append(a.Entries, Entry{})
		p.parent = append(p.parent, fr.entry)
		p.names = append(p.names, "")
		fr.entry = len(a.Entries) - 1
	case kSig:
		fr.sig = 0
		if string(localName(p.open[fr.name:])) == "x-signature" {
			fr.sig = 1
		}
		if p.styles[fr.sig] == "" {
			p.styles[fr.sig] = style
		}
	case kEncoding:
		a.Entries[fr.entry].Encoding = style
	}
	if fr.kind.kept() {
		p.text = p.text[:0]
	}
	p.stack = append(p.stack, fr)
	if empty {
		return p.end()
	}
	return false, nil
}

// end closes the innermost element, reporting whether it was the root.
func (p *tocParser) end() (bool, error) {
	n := len(p.stack)
	fr := p.stack[n-1]
	p.stack, p.open = p.stack[:n-1], p.open[:fr.name]
	if !fr.kind.kept() {
		return n == 1, nil
	}
	if !utf8.Valid(p.text) {
		return false, errors.New("invalid UTF-8 in element text")
	}
	if fr.kind == kCert {
		if len(p.certs[0])+len(p.certs[1]) < maxTOCCerts {
			p.certs[fr.sig] = append(p.certs[fr.sig], string(p.text))
		}
		p.text = p.text[:0]
		return false, nil
	}
	s := string(p.text)
	p.text = p.text[:0]
	e := &p.a.Entries[fr.entry]
	var err error
	switch fr.kind {
	case kName:
		if len(s) > maxTOCName {
			return false, errors.New("file name too long")
		}
		p.names[fr.entry] = s
	case kType:
		e.Type = s
	case kLink:
		e.Link = s
	case kOffset:
		e.Offset, err = parseInt(s)
	case kLength:
		e.Length, err = parseInt(s)
	case kSize:
		e.Size, err = parseInt(s)
	}
	return false, err
}

// parseInt reads an integer element, empty meaning 0 as with xml.Unmarshal.
func parseInt(s string) (int64, error) {
	if s = strings.TrimSpace(s); s == "" {
		return 0, nil
	}
	return strconv.ParseInt(s, 10, 64)
}
