// Command-line harness for the Quick Look index lookup. Builds a fabricated
// binchk index (schema version 2) in a temporary directory and checks every
// lookup path.
// usage: quicklook-tests [scratch-dir]

import CryptoKit
import Darwin
import Foundation

var failures = 0
var checks = 0

@MainActor func check(_ cond: Bool, _ what: String, line: UInt = #line) {
    checks += 1
    if !cond {
        failures += 1
        print("FAIL \(line): \(what)")
    }
}

func sha(_ d: Data) -> String { BinchkIndex.hex(SHA256.hash(data: d)) }
func sha(_ s: String) -> String { sha(Data(s.utf8)) }

let fm = FileManager.default
let base: String = {
    let parent = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : NSTemporaryDirectory()
    try! fm.createDirectory(atPath: parent, withIntermediateDirectories: true)
    var tmpl = Array((parent as NSString).appendingPathComponent("binchk-ql.XXXXXX").utf8CString)
    guard mkdtemp(&tmpl) != nil else { fatalError("mkdtemp failed") }
    // Canonical path, so /tmp vs /private/tmp does not muddle the pointer cases.
    // realpath, not resolvingSymlinksInPath: Foundation maps /private/tmp
    // back to /tmp, which is not the canonical spelling.
    guard let real = realpath(tmpl, nil) else { fatalError("realpath failed") }
    defer { free(real) }
    return String(cString: real)
}()

let indexDir = base + "/data/index"
let files = base + "/files"
for d in ["entries", "paths", "content"] {
    try! fm.createDirectory(atPath: indexDir + "/" + d, withIntermediateDirectories: true)
}
try! fm.createDirectory(atPath: files, withIntermediateDirectories: true)

/// Writes through POSIX so the name's bytes are exactly the string's UTF-8
/// (no Foundation file-system representation in between).
func write(_ path: String, _ data: Data) {
    let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
    precondition(fd >= 0, "open \(path)")
    data.withUnsafeBytes { b in
        if b.count > 0 { precondition(Darwin.write(fd, b.baseAddress!, b.count) == b.count) }
    }
    close(fd)
}

func mkdir(_ path: String) {
    try! FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
}

func card(_ label: String) -> Data {
    Data("<!doctype html><html><body class=\"v-Clean\"><div class=\"card\"><p>card \(label)</p></div></body></html>".utf8)
}

/// An entry: its card and the JSON head the reader checks.
func addEntry(_ id: String, kind: String = "file", key: String, html: Data? = nil, label: String = "") {
    write(indexDir + "/entries/" + id + ".html", html ?? card(label))
    let json = #"{"version":2,"entry_id":"\#(id)","content_key":"\#(key)","kind":"\#(kind)","path":"/x","file_name":"x"}"#
    write(indexDir + "/entries/" + id + ".json", Data(json.utf8))
}

func addContent(key: String, entry: String, path: String, at: String = "2026-10-08T13:03:04Z") {
    let json = #"{"version":2,"entry":"\#(entry)","path":"\#(path)","analyzed_at":"\#(at)"}"#
    write(indexDir + "/content/" + key + ".json", Data(json.utf8))
}

func pointerFile(_ path: String) -> String { indexDir + "/paths/" + sha(path) + ".json" }

func addFilePointer(path: String, entry: String, size: Int64, mtimeNs: Int64, kind: String = "file") {
    let json = #"{"version":2,"entry":"\#(entry)","kind":"\#(kind)","size":\#(size),"mtime_unix_ns":\#(mtimeNs)}"#
    write(pointerFile(path), Data(json.utf8))
}

func addBundlePointer(path: String, entry: String, tree: BinchkIndex.Tree, exe: BinchkIndex.FileStat) {
    let json = #"{"version":2,"entry":"\#(entry)","kind":"bundle","tree_entries":\#(tree.entries),"tree_size":\#(tree.size),"tree_mtime_unix_ns":\#(tree.mtimeNs),"exec_size":\#(exe.size),"exec_mtime_unix_ns":\#(exe.mtimeNs)}"#
    write(pointerFile(path), Data(json.utf8))
}

func setMtime(_ path: String, sec: Int, nsec: Int) {
    var ts = [timespec(tv_sec: sec, tv_nsec: nsec), timespec(tv_sec: sec, tv_nsec: nsec)]
    precondition(utimensat(AT_FDCWD, path, &ts, 0) == 0)
}

func id(_ s: String) -> String { sha("entry " + s) }

let idx = BinchkIndex(indexDir: indexDir)
func html(_ r: PreviewResult) -> String { String(decoding: r.html, as: UTF8.self) }
func viaContent(_ o: PreviewOutcome) -> Bool {
    if case .indexed(_, .content) = o { return true }
    return false
}

// 1. File pointer hit: the pointer names an entry whose content key is NOT
//    the file's hash, so finding its card proves the file was not hashed.
do {
    let f = files + "/tool"
    let body = Data("pointer-hit".utf8)
    write(f, body)
    setMtime(f, sec: 1_700_000_000, nsec: 123_456_789)
    let fake = id("fake")
    addEntry(fake, key: String(repeating: "a", count: 64), label: "fake")
    addFilePointer(path: f, entry: fake, size: Int64(body.count), mtimeNs: 1_700_000_000_123_456_789)
    let r = idx.preview(forPath: f)
    check(r.outcome == .indexed(entry: fake, via: .pointer), "pointer hit: \(r.outcome)")
    check(html(r).contains("card fake") && !html(r).contains("class=\"match\""), "pointer hit returns the stored card, no banner")

    // 2. Stale pointer (mtime moved): fall back to the content map, and say so.
    let real = id("real")
    addEntry(real, key: sha(body), label: "real")
    addContent(key: sha(body), entry: real, path: "/Users/u/Downloads/<b>orig&.bin")
    setMtime(f, sec: 1_700_000_001, nsec: 0)
    let r2 = idx.preview(forPath: f)
    check(r2.outcome == .indexed(entry: real, via: .content(path: "/Users/u/Downloads/<b>orig&.bin", analyzedAt: "2026-10-08T13:03:04Z", bundle: false)), "stale mtime: \(r2.outcome)")
    let h2 = html(r2)
    check(h2.contains("card real"), "stale mtime returns the content match's card")
    check(h2.contains("<div class=\"card\"><div class=\"match\">Not checked at this location. Same contents as"), "banner at the top of the card")
    check(h2.contains("Same contents as <b>&lt;b&gt;orig&amp;.bin</b>, checked in /Users/u/Downloads on "), "banner names the analysis, escaped: \(h2)")
    check(!h2.contains("<b>orig") && h2.contains("Oct 2026"), "no raw markup in the banner; a readable date")

    // Stale size (same mtime as the pointer): also by content.
    setMtime(f, sec: 1_700_000_000, nsec: 123_456_789)
    addFilePointer(path: f, entry: fake, size: Int64(body.count) + 1, mtimeNs: 1_700_000_000_123_456_789)
    check(viaContent(idx.preview(forPath: f).outcome), "stale size uses the content map")

    // Malformed, old-schema or wrong-kind pointers are ignored, never followed.
    for bad in [#"{"version":2,"entry":"../../etc/passwd","kind":"file","size":11,"mtime_unix_ns":1700000000123456789}"#,
                #"{"version":2,"entry":"\#(String(repeating: "A", count: 64))","kind":"file","size":11,"mtime_unix_ns":1700000000123456789}"#,
                #"{"sha256":"\#(fake)","size":11,"mtime_unix_ns":1700000000123456789}"#,
                #"{"version":1,"entry":"\#(fake)","kind":"file","size":11,"mtime_unix_ns":1700000000123456789}"#,
                #"{"version":2,"entry":"\#(fake)","kind":"bundle","size":11,"mtime_unix_ns":1700000000123456789}"#,
                #"{"version":2,"entry":"\#(fake)","kind":"file"}"#,
                "not json"] {
        write(pointerFile(f), Data(bad.utf8))
        check(viaContent(idx.preview(forPath: f).outcome), "bad pointer ignored: \(bad)")
    }

    // A pointer whose entry is missing, or of another kind, is not used.
    addFilePointer(path: f, entry: id("missing"), size: Int64(body.count), mtimeNs: 1_700_000_000_123_456_789)
    check(viaContent(idx.preview(forPath: f).outcome), "pointer to a missing entry")
    let bundleEntry = id("bundle-entry")
    addEntry(bundleEntry, kind: "bundle", key: sha(body), label: "bundle")
    addFilePointer(path: f, entry: bundleEntry, size: Int64(body.count), mtimeNs: 1_700_000_000_123_456_789)
    check(viaContent(idx.preview(forPath: f).outcome), "pointer to a bundle entry from a file")

    // A symlinked pointer file is not trusted.
    let realPtr = base + "/pointer.json"
    write(realPtr, Data(#"{"version":2,"entry":"\#(fake)","kind":"file","size":\#(body.count),"mtime_unix_ns":1700000000123456789}"#.utf8))
    try? fm.removeItem(atPath: pointerFile(f))
    try! fm.createSymbolicLink(atPath: pointerFile(f), withDestinationPath: realPtr)
    check(viaContent(idx.preview(forPath: f).outcome), "symlinked pointer ignored")

    // Path spellings binchk would record identically.
    try? fm.removeItem(atPath: pointerFile(f))
    addFilePointer(path: f, entry: fake, size: Int64(body.count), mtimeNs: 1_700_000_000_123_456_789)
    check(idx.preview(forPath: files + "/./x/../tool").outcome == .indexed(entry: fake, via: .pointer), "dot segments")

    // The content map is checked against the entry it names.
    let g = files + "/other"
    let gb = Data("other-body".utf8)
    write(g, gb)
    addEntry(id("wrong-key"), key: sha("something else"), label: "wrong key")
    addContent(key: sha(gb), entry: id("wrong-key"), path: "/x/other")
    check(idx.preview(forPath: g).outcome == .notChecked(.noEntry), "content map to an entry with another key")
    addEntry(id("wrong-kind"), kind: "bundle", key: sha(gb), label: "wrong kind")
    addContent(key: sha(gb), entry: id("wrong-kind"), path: "/x/other")
    check(idx.preview(forPath: g).outcome == .notChecked(.noEntry), "content map to an entry of another kind")
    write(indexDir + "/content/" + sha(gb) + ".json", Data(#"{"version":2,"entry":"../x","path":"/x","analyzed_at":"x"}"#.utf8))
    check(idx.preview(forPath: g).outcome == .notChecked(.noEntry), "malformed content map")
}

// 2. The cross-language vector: the same bundle as makeVector in
//    internal/bundleid/bundleid_test.go must give the same fingerprint.
let vectorFingerprint = "1d8f31b6913db5d53d3d478a16d60e1d1ae00cac889ac399bc2e45de22688466"
let vectorMainSHA256 = "da4181a93733269869e10cd396dacad3eff5c8f4713ffe53bf946ddcdd196904"

func makeVector(_ dir: String) -> String {
    let app = dir + "/Vector.app"
    let files: [(String, String)] = [
        ("Contents/Info.plist", """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict><key>CFBundleExecutable</key><string>Vector</string></dict></plist>

        """),
        ("Contents/MacOS/Vector", "vector main executable\n"),
        ("Contents/_CodeSignature/CodeResources", "code resources\n"),
        ("Contents/Resources/a.txt", "alpha"),
        ("Contents/Resources/b/x", ""),
        ("Contents/Resources/caf\u{e9}.txt", "unicode"),
    ]
    for (p, d) in files {
        mkdir(((app + "/" + p) as NSString).deletingLastPathComponent)
        write(app + "/" + p, Data(d.utf8))
    }
    mkdir(app + "/Contents/Resources/b-c")
    precondition(symlink("../MacOS/Vector", app + "/Contents/Resources/link") == 0)
    precondition(symlink("nowhere/at all", app + "/Contents/Resources/dangling") == 0)
    return app
}

do {
    let dir = base + "/vector"
    mkdir(dir)
    let app = makeVector(dir)
    check(BinchkIndex.sha256File(app + "/Contents/MacOS/Vector") == vectorMainSHA256, "vector main executable hash")
    guard let w = BinchkIndex.walk(root: app, maxEntries: 1000, budget: 10) else { fatalError("vector walk") }
    let lines = w.manifest.map { String(decoding: $0.path, as: UTF8.self) + " " + String(UnicodeScalar($0.type)) + " " + String(decoding: $0.value, as: UTF8.self) }
    let want = [
        "Contents d ",
        "Contents/Info.plist f 134",
        "Contents/MacOS d ",
        "Contents/MacOS/Vector f 23",
        "Contents/Resources d ",
        "Contents/Resources/a.txt f 5",
        "Contents/Resources/b d ",
        "Contents/Resources/b-c d ",
        "Contents/Resources/b/x f 0",
        "Contents/Resources/caf\u{e9}.txt f 7",
        "Contents/Resources/dangling l nowhere/at all",
        "Contents/Resources/link l ../MacOS/Vector",
        "Contents/_CodeSignature d ",
        "Contents/_CodeSignature/CodeResources f 15",
    ]
    check(lines == want, "vector manifest: \(lines)")
    check(w.tree.entries == 15, "vector tree counts the root: \(w.tree.entries)")
    let fp = BinchkIndex.bundleFingerprint(root: app, mainSHA256: vectorMainSHA256, manifest: w.manifest)
    check(fp == vectorFingerprint, "vector fingerprint \(fp ?? "nil")")

    // The preview finds it by fingerprint, through the content map.
    let e = id("vector")
    addEntry(e, kind: "bundle", key: vectorFingerprint, label: "vector")
    addContent(key: vectorFingerprint, entry: e, path: "/Users/u/Downloads/Vector.app")
    let r = idx.preview(forPath: app)
    check(r.outcome == .indexed(entry: e, via: .content(path: "/Users/u/Downloads/Vector.app", analyzedAt: "2026-10-08T13:03:04Z", bundle: true)), "bundle by fingerprint: \(r.outcome)")
    check(html(r).contains("another copy") && html(r).contains("file contents were not compared") && html(r).contains("card vector"), "bundle by fingerprint shows the weaker banner")

    // A fresh bundle pointer: tree summary and main executable unchanged.
    let pe = id("vector-pointer")
    addEntry(pe, kind: "bundle", key: sha("not the fingerprint"), label: "vector pointer")
    let exe = BinchkIndex.statRegular(app + "/Contents/MacOS/Vector")!
    addBundlePointer(path: app, entry: pe, tree: w.tree, exe: exe)
    check(idx.preview(forPath: app + "/").outcome == .indexed(entry: pe, via: .pointer), "bundle pointer hit")
    // Through a symlinked parent the pointer is found by the resolved path.
    precondition(symlink(dir, base + "/vlink") == 0)
    check(idx.preview(forPath: base + "/vlink/Vector.app").outcome == .indexed(entry: pe, via: .pointer), "bundle pointer via resolved path")

    // Anything added to the bundle makes the pointer stale and changes the
    // fingerprint: a trojanized copy is not the bundle that was analysed.
    write(app + "/Contents/Resources/payload.dylib", Data("payload".utf8))
    check(idx.preview(forPath: app).outcome == .notChecked(.noEntry), "changed bundle is not matched")
    unlink(app + "/Contents/Resources/payload.dylib")
    // A changed main executable (same tree size) also invalidates the pointer.
    setMtime(app + "/Contents/MacOS/Vector", sec: 1_600_000_000, nsec: 0)
    check(viaContent(idx.preview(forPath: app).outcome), "main executable mtime makes the pointer stale")

    // A pointer of the wrong kind for a bundle is ignored.
    addFilePointer(path: app, entry: pe, size: exe.size, mtimeNs: exe.mtimeNs)
    check(viaContent(idx.preview(forPath: app).outcome), "file pointer for a bundle ignored")

    // Too many entries to walk: not looked up, even with a pointer.
    var small = idx
    small.maxWalkEntries = 5
    check(small.preview(forPath: app).outcome == .notChecked(.tooLarge), "bundle walk cap")
    var slow = idx
    slow.walkBudget = 0
    _ = slow.preview(forPath: app) // the budget is checked every 1024 entries; just must not crash
}

// 3. Bundles binchk refuses to identify.
do {
    func app(_ name: String, exe: Any?, plistLink: Bool = false) -> String {
        let a = files + "/" + name
        mkdir(a + "/Contents/MacOS")
        write(a + "/Contents/MacOS/Tool", Data("tool".utf8))
        var plist: [String: Any] = ["CFBundleIdentifier": "test"]
        if let exe { plist["CFBundleExecutable"] = exe }
        let data = try! PropertyListSerialization.data(fromPropertyList: plist, format: .binary, options: 0)
        if plistLink {
            write(base + "/" + name + ".plist", data)
            precondition(symlink(base + "/" + name + ".plist", a + "/Contents/Info.plist") == 0)
        } else {
            write(a + "/Contents/Info.plist", data)
        }
        return a
    }
    for (name, exe) in [("Up.app", "../../tool"), ("Dot.app", "."), ("DotDot.app", ".."), ("Empty.app", ""),
                        ("Slash.app", "MacOS/Tool"), ("Esc.app", "../../../benign-outside")] {
        let r = idx.preview(forPath: app(name, exe: exe))
        check(r.outcome == .notChecked(.unreadable), "CFBundleExecutable \(exe) refused: \(r.outcome)")
        check(html(r).contains("Not checked by binchk"), "\(name) gets the fallback card")
    }
    check(idx.preview(forPath: app("NoExe.app", exe: nil)).outcome == .notChecked(.unreadable), "no CFBundleExecutable")
    check(idx.preview(forPath: app("Num.app", exe: 5)).outcome == .notChecked(.unreadable), "non-string CFBundleExecutable")
    check(idx.preview(forPath: app("Link.app", exe: "Tool", plistLink: true)).outcome == .notChecked(.unreadable), "symlinked Info.plist")
    check(BinchkIndex.validExecutableName("Foo Helper") && BinchkIndex.validExecutableName(".hidden"), "valid names")
    // A binary plist with a valid name is read.
    let ok = app("Ok.app", exe: "Tool")
    check(BinchkIndex.mainExecutable(forBundle: ok) == ok + "/Contents/MacOS/Tool", "binary Info.plist")
    check(idx.preview(forPath: ok).outcome == .notChecked(.noEntry), "valid bundle without an entry")
    // A plain directory is not something binchk indexes.
    check(idx.preview(forPath: ok + "/Contents").outcome == .notChecked(.unreadable), "plain directory")
}

// 4. Missing entry: the built-in card, with the name escaped.
do {
    let f = files + "/<b>new&\"tool\".exe"
    write(f, Data("never-seen".utf8))
    let r = idx.preview(forPath: f)
    check(r.outcome == .notChecked(.noEntry), "missing entry: \(r.outcome)")
    let h = html(r)
    check(h.contains("Not checked by binchk"), "fallback card title")
    check(h.contains("binchk scan"), "fallback card hint")
    check(h.contains("&lt;b&gt;new&amp;&quot;tool&quot;.exe"), "file name escaped")
    check(!h.contains("<b>new"), "no raw markup from the file name")
    check(h.contains("prefers-color-scheme:dark"), "fallback card has a dark variant")
    check(!h.contains("<script") && !h.contains("http"), "fallback card is self-contained")

    check(idx.preview(forPath: files + "/does-not-exist").outcome == .notChecked(.unreadable), "nonexistent file")
    check(BinchkIndex(indexDir: base + "/nope").preview(forPath: f).outcome == .notChecked(.noEntry), "no index at all")
    var noIndex = BinchkIndex(indexDir: base + "/nope")
    noIndex.maxHashBytes = 1 // would report tooLarge if it got as far as hashing
    check(noIndex.preview(forPath: f).outcome == .notChecked(.noEntry), "no index: file is never hashed")
    noIndex.maxWalkEntries = 1 // would report tooLarge if it walked
    check(noIndex.preview(forPath: base + "/vector/Vector.app").outcome == .notChecked(.noEntry), "no index: bundle is never walked")
}

// 5. Oversized or invalid cards.
do {
    func indexed(_ label: String, card: Data) -> String {
        let f = files + "/" + label
        let body = Data(label.utf8)
        write(f, body)
        addEntry(id(label), key: sha(body), html: card)
        addContent(key: sha(body), entry: id(label), path: f)
        return f
    }
    let f = indexed("big-card", card: Data(repeating: 0x41, count: BinchkIndex.defaultMaxEntryBytes + 1))
    let r = idx.preview(forPath: f)
    check(r.outcome == .notChecked(.invalidEntry), "oversized card: \(r.outcome)")
    check(html(r).contains("Not checked by binchk"), "oversized card gets the fallback card")
    write(indexDir + "/entries/" + id("big-card") + ".html", Data(repeating: 0x41, count: BinchkIndex.defaultMaxEntryBytes))
    check(viaContent(idx.preview(forPath: f).outcome), "card at the size cap loads")
    write(indexDir + "/entries/" + id("big-card") + ".html", Data())
    check(idx.preview(forPath: f).outcome == .notChecked(.invalidEntry), "empty card")

    let g = indexed("dir-card", card: card("x"))
    unlink(indexDir + "/entries/" + id("dir-card") + ".html")
    mkdir(indexDir + "/entries/" + id("dir-card") + ".html")
    check(idx.preview(forPath: g).outcome == .notChecked(.invalidEntry), "directory card")

    let h = indexed("fifo-card", card: card("x"))
    unlink(indexDir + "/entries/" + id("fifo-card") + ".html")
    precondition(mkfifo(indexDir + "/entries/" + id("fifo-card") + ".html", 0o644) == 0)
    check(idx.preview(forPath: h).outcome == .notChecked(.invalidEntry), "FIFO card does not hang")

    // An oversized or symlinked entry JSON is not read.
    let j = indexed("big-json", card: card("x"))
    write(indexDir + "/entries/" + id("big-json") + ".json", Data(repeating: 0x20, count: BinchkIndex.maxJSONBytes + 1))
    check(idx.preview(forPath: j).outcome == .notChecked(.noEntry), "oversized entry JSON")
    let k = indexed("link-json", card: card("x"))
    let target = base + "/entry.json"
    try! fm.moveItem(atPath: indexDir + "/entries/" + id("link-json") + ".json", toPath: target)
    precondition(symlink(target, indexDir + "/entries/" + id("link-json") + ".json") == 0)
    check(idx.preview(forPath: k).outcome == .notChecked(.noEntry), "symlinked entry JSON")

    // A FIFO as the previewed file itself is not opened.
    precondition(mkfifo(files + "/fifo", 0o644) == 0)
    check(idx.preview(forPath: files + "/fifo").outcome == .notChecked(.unreadable), "FIFO file")
}

// 6. Symlinked card: refused even though the target is a valid card.
do {
    let f = files + "/linked"
    let body = Data("linked-body".utf8)
    write(f, body)
    let target = base + "/elsewhere.html"
    write(target, card("elsewhere"))
    addEntry(id("linked"), key: sha(body))
    addContent(key: sha(body), entry: id("linked"), path: f)
    unlink(indexDir + "/entries/" + id("linked") + ".html")
    try! fm.createSymbolicLink(atPath: indexDir + "/entries/" + id("linked") + ".html", withDestinationPath: target)
    let r = idx.preview(forPath: f)
    check(r.outcome == .notChecked(.invalidEntry), "symlinked card: \(r.outcome)")
    check(!html(r).contains("card elsewhere"), "symlink target not shown")

    // The previewed file itself may be a symlink (Go's os.Stat follows it):
    // its target's pointer is found through the resolved path.
    try! fm.createSymbolicLink(atPath: files + "/alias", withDestinationPath: files + "/tool")
    check(idx.preview(forPath: files + "/alias").outcome == .indexed(entry: id("fake"), via: .pointer), "symlinked file is followed")
}

// 7. Large files: no hashing without a pointer; a pointer still works.
do {
    var small = idx
    small.maxHashBytes = 1024
    let f = files + "/huge.dmg"
    let body = Data(repeating: 0, count: 2048)
    write(f, body)
    addEntry(id("huge"), key: sha(body), label: "huge")
    addContent(key: sha(body), entry: id("huge"), path: f)
    check(small.preview(forPath: f).outcome == .notChecked(.tooLarge), "too large without pointer")
    let st = BinchkIndex.statRegular(f)!
    addFilePointer(path: f, entry: id("huge"), size: st.size, mtimeNs: st.mtimeNs)
    check(small.preview(forPath: f).outcome == .indexed(entry: id("huge"), via: .pointer), "too large with pointer")

    // The real limit, on a sparse file: answered without reading it.
    let sparse = files + "/sparse.bin"
    precondition(fm.createFile(atPath: sparse, contents: nil))
    precondition(truncate(sparse, BinchkIndex.defaultMaxHashBytes + 1) == 0)
    let t0 = Date()
    check(idx.preview(forPath: sparse).outcome == .notChecked(.tooLarge), "1 GiB + 1 is too large")
    check(Date().timeIntervalSince(t0) < 1, "too-large answer is immediate")
}

// 8. Hashing matches shasum on a multi-chunk file.
do {
    var bytes = [UInt8](repeating: 0, count: 3 << 20 + 17)
    for i in bytes.indices { bytes[i] = UInt8(truncatingIfNeeded: i &* 31 &+ 7) }
    let f = files + "/chunks"
    write(f, Data(bytes))
    check(BinchkIndex.sha256File(f) == sha(Data(bytes)), "streaming hash")
    try! fm.createSymbolicLink(atPath: files + "/chunks-link", withDestinationPath: f)
    check(BinchkIndex.sha256File(files + "/chunks-link", followLinks: false) == nil, "no-follow hash refuses a link")
}

// 9. Banner placement on cards without the expected markup.
do {
    let b = BinchkIndex.banner(analysedPath: "/a/b", analyzedAt: "not a date")
    check(b.contains("on not a date"), "unparseable date shown as is")
    let plain = String(decoding: BinchkIndex.injectBanner(Data("<html><body class=x><p>c</p></body></html>".utf8), banner: "[B]"), as: UTF8.self)
    check(plain == "<html><body class=x>[B]<p>c</p></body></html>", "banner after <body>: \(plain)")
    let bare = String(decoding: BinchkIndex.injectBanner(Data("<p>c</p>".utf8), banner: "[B]"), as: UTF8.self)
    check(bare == "[B]<p>c</p>", "banner prepended: \(bare)")
}

// 10. Normalisation.
check(BinchkIndex.normalize("/a/b/") == "/a/b", "trailing slash")
check(BinchkIndex.normalize("/a/./b/../c") == "/a/c", "dot segments")
check(BinchkIndex.normalize("/") == "/", "root")
check(BinchkIndex.isDigest(String(repeating: "0", count: 64)), "digest ok")
check(!BinchkIndex.isDigest(String(repeating: "0", count: 63)), "short digest")
check(!BinchkIndex.isDigest(String(repeating: "g", count: 64)), "non-hex digest")

// 11. Default index dir is the real home, not a container.
check(BinchkIndex.defaultIndexDir().hasSuffix("/Library/Application Support/binchk/index"), "default index dir")
check(!BinchkIndex.defaultIndexDir().contains("/Library/Containers/"), "default index dir outside containers")

if failures == 0 { try? fm.removeItem(atPath: base) } else { print("left fixtures in \(base)") }
print("\(checks - failures)/\(checks) checks passed")
exit(failures == 0 ? 0 : 1)
