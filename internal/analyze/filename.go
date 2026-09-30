package analyze

import (
	"path/filepath"
	"strings"

	"github.com/danczar/binchk/internal/detect"
)

var docExts = map[string]bool{
	"pdf": true, "doc": true, "docx": true, "xls": true, "xlsx": true, "ppt": true, "pptx": true, "txt": true, "rtf": true,
	"jpg": true, "jpeg": true, "png": true, "gif": true, "bmp": true, "mp3": true, "mp4": true, "mov": true, "avi": true,
	"wav": true, "zip": true, "rar": true, "7z": true, "csv": true, "html": true, "htm": true, "odt": true, "pages": true,
	"key": true, "numbers": true, "heic": true, "webp": true, "svg": true, "eml": true, "msg": true, "iso": true,
}

var winExecExts = map[string]bool{
	"exe": true, "scr": true, "com": true, "pif": true, "cpl": true, "dll": true, "sys": true, "ocx": true, "efi": true,
	"drv": true, "msi": true, "bat": true, "cmd": true,
}

// filenameFindings flags names built to trick a user into running a binary.
func filenameFindings(name string, format detect.Format) []Finding {
	var out []Finding
	add := func(id, title, detail string, sev Severity, ev ...string) {
		out = append(out, Finding{ID: id, Title: title, Detail: detail, Severity: sev, Category: "filename", Evidence: ev})
	}
	if strings.ContainsAny(name, "‮‭‏⁦⁧⁨") {
		add("name-bidi", "Filename contains a right-to-left override", "Unicode direction tricks make \"cod.exe\" display as \"exe.doc\".", High, name)
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	inner := strings.ToLower(strings.TrimPrefix(filepath.Ext(stem), "."))
	if docExts[inner] && (winExecExts[ext] || ext == "app" || ext == "") && ext != inner {
		add("name-double-ext", "Double file extension", "A document-looking name hiding an executable extension.", High, name)
	}
	if docExts[ext] {
		add("name-disguised", "Executable disguised as a document or media file", "The extension says ."+ext+" but the content is a "+string(format)+" executable.", High, name)
	}
	if strings.Contains(stem, "     ") {
		add("name-padding", "Filename padded with spaces", "Long runs of spaces push the real extension out of view.", Medium, name)
	}
	if format == detect.PE && (ext == "scr" || ext == "pif" || ext == "com" || ext == "cpl") {
		add("name-rare-exec-ext", "Rarely legitimate executable extension", "."+ext+" files are executables that many users don't recognise as programs.", Medium, name)
	}
	return out
}
