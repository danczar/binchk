// Command-line harness for the Quick Look index lookup. Builds a fabricated
// binchk index in a temporary directory and checks every lookup path.
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
try! fm.createDirectory(atPath: indexDir + "/paths", withIntermediateDirectories: true)
try! fm.createDirectory(atPath: files, withIntermediateDirectories: true)

func write(_ path: String, _ data: Data) {
    try! data.write(to: URL(fileURLWithPath: path))
}

func card(_ label: String) -> Data { Data("<!doctype html><p>card \(label)</p>".utf8) }

func addEntry(_ digest: String, _ html: Data) {
    write(indexDir + "/" + digest + ".html", html)
}

func addPointer(path: String, digest: String, size: Int64, mtimeNs: Int64) {
    let key = sha(Data(path.utf8))
    let json = #"{"sha256":"\#(digest)","size":\#(size),"mtime_unix_ns":\#(mtimeNs)}"#
    write(indexDir + "/paths/" + key + ".json", Data(json.utf8))
}

func setMtime(_ path: String, sec: Int, nsec: Int) {
    var ts = [timespec(tv_sec: sec, tv_nsec: nsec), timespec(tv_sec: sec, tv_nsec: nsec)]
    precondition(utimensat(AT_FDCWD, path, &ts, 0) == 0)
}

let idx = BinchkIndex(indexDir: indexDir)
func html(_ r: PreviewResult) -> String { String(decoding: r.html, as: UTF8.self) }

// 1. Pointer hit: the pointer names a digest that is NOT the file's hash, so
//    finding its card proves the file was not hashed.
do {
    let f = files + "/tool"
    let body = Data("pointer-hit".utf8)
    write(f, body)
    setMtime(f, sec: 1_700_000_000, nsec: 123_456_789)
    let fake = String(repeating: "a", count: 64)
    addEntry(fake, card("fake"))
    addPointer(path: f, digest: fake, size: Int64(body.count), mtimeNs: 1_700_000_000_123_456_789)
    let r = idx.preview(forPath: f)
    check(r.outcome == .indexed(sha256: fake, via: .pointer), "pointer hit: \(r.outcome)")
    check(html(r).contains("card fake"), "pointer hit returns the stored card")

    // 2. Stale pointer (mtime moved): fall back to hashing.
    addEntry(sha(body), card("real"))
    setMtime(f, sec: 1_700_000_001, nsec: 0)
    let r2 = idx.preview(forPath: f)
    check(r2.outcome == .indexed(sha256: sha(body), via: .hash), "stale mtime hashes: \(r2.outcome)")
    check(html(r2).contains("card real"), "stale mtime returns the real card")

    // Stale size (same mtime as the pointer): also hashes.
    setMtime(f, sec: 1_700_000_000, nsec: 123_456_789)
    addPointer(path: f, digest: fake, size: Int64(body.count) + 1, mtimeNs: 1_700_000_000_123_456_789)
    check(idx.preview(forPath: f).outcome == .indexed(sha256: sha(body), via: .hash), "stale size hashes")

    // Malformed pointers are ignored, never followed.
    for bad in [#"{"sha256":"../../etc/passwd","size":11,"mtime_unix_ns":1700000000123456789}"#,
                #"{"sha256":"\#(String(repeating: "A", count: 64))","size":11,"mtime_unix_ns":1700000000123456789}"#,
                "not json"] {
        write(indexDir + "/paths/" + sha(Data(f.utf8)) + ".json", Data(bad.utf8))
        check(idx.preview(forPath: f).outcome == .indexed(sha256: sha(body), via: .hash), "malformed pointer ignored: \(bad)")
    }

    // A pointer whose digest has no entry falls back to hashing.
    addPointer(path: f, digest: String(repeating: "b", count: 64), size: Int64(body.count), mtimeNs: 1_700_000_000_123_456_789)
    check(idx.preview(forPath: f).outcome == .indexed(sha256: sha(body), via: .hash), "pointer to a missing entry hashes")

    // A symlinked pointer file is not trusted.
    let key = sha(Data(f.utf8))
    let real = base + "/pointer.json"
    write(real, Data(#"{"sha256":"\#(fake)","size":\#(body.count),"mtime_unix_ns":1700000000123456789}"#.utf8))
    try? fm.removeItem(atPath: indexDir + "/paths/" + key + ".json")
    try! fm.createSymbolicLink(atPath: indexDir + "/paths/" + key + ".json", withDestinationPath: real)
    check(idx.preview(forPath: f).outcome == .indexed(sha256: sha(body), via: .hash), "symlinked pointer ignored")

    // Path spellings binchk would record identically.
    check(idx.preview(forPath: files + "/./x/../tool").outcome == .indexed(sha256: sha(body), via: .hash), "dot segments")
}

// 3. Application bundle: keyed by the main executable; pointer keyed by the
//    bundle path (no trailing slash) with the executable's size and mtime.
do {
    let app = files + "/Foo.app"
    try! fm.createDirectory(atPath: app + "/Contents/MacOS", withIntermediateDirectories: true)
    let plist: [String: Any] = ["CFBundleExecutable": "Foo Helper", "CFBundleIdentifier": "test.foo"]
    // Binary plist, as most shipped apps have.
    write(app + "/Contents/Info.plist", try! PropertyListSerialization.data(fromPropertyList: plist, format: .binary, options: 0))
    let exe = Data("main-executable".utf8)
    write(app + "/Contents/MacOS/Foo Helper", exe)
    addEntry(sha(exe), card("bundle"))
    let r = idx.preview(forPath: app + "/")
    check(r.outcome == .indexed(sha256: sha(exe), via: .hash), "bundle hashes main executable: \(r.outcome)")
    check(html(r).contains("card bundle"), "bundle card")

    setMtime(app + "/Contents/MacOS/Foo Helper", sec: 1_600_000_000, nsec: 5)
    let fake = String(repeating: "c", count: 64)
    addEntry(fake, card("bundle-pointer"))
    addPointer(path: app, digest: fake, size: Int64(exe.count), mtimeNs: 1_600_000_000_000_000_005)
    check(idx.preview(forPath: app + "/").outcome == .indexed(sha256: fake, via: .pointer), "bundle pointer hit")

    // Through a symlinked parent directory the pointer is found by the
    // resolved path.
    try! fm.createSymbolicLink(atPath: base + "/link", withDestinationPath: files)
    let rl = idx.preview(forPath: base + "/link/Foo.app")
    check(rl.outcome == .indexed(sha256: fake, via: .pointer), "pointer via resolved path: \(rl.outcome)")

    // A CFBundleExecutable that tries to leave Contents/MacOS is refused.
    let evil = files + "/Evil.app"
    try! fm.createDirectory(atPath: evil + "/Contents/MacOS", withIntermediateDirectories: true)
    write(evil + "/Contents/Info.plist", try! PropertyListSerialization.data(fromPropertyList: ["CFBundleExecutable": "../../tool"], format: .xml, options: 0))
    let re = idx.preview(forPath: evil)
    check(re.outcome == .notChecked(.unreadable), "escaping CFBundleExecutable refused: \(re.outcome)")
    check(html(re).contains("Not checked by binchk"), "escaping bundle gets the fallback card")

    // A plain directory is not something binchk indexes.
    check(idx.preview(forPath: files + "/Foo.app/Contents").outcome == .notChecked(.unreadable), "plain directory")
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
}

// 5. Oversized or invalid index entries.
do {
    let f = files + "/big-card"
    let body = Data("big-card-body".utf8)
    write(f, body)
    addEntry(sha(body), Data(repeating: 0x41, count: BinchkIndex.defaultMaxEntryBytes + 1))
    let r = idx.preview(forPath: f)
    check(r.outcome == .notChecked(.invalidEntry), "oversized entry: \(r.outcome)")
    check(html(r).contains("Not checked by binchk"), "oversized entry gets the fallback card")

    addEntry(sha(body), Data(repeating: 0x41, count: BinchkIndex.defaultMaxEntryBytes))
    check(idx.preview(forPath: f).outcome == .indexed(sha256: sha(body), via: .hash), "entry at the size cap loads")

    addEntry(sha(body), Data())
    check(idx.preview(forPath: f).outcome == .notChecked(.invalidEntry), "empty entry")

    let g = files + "/dir-card"
    let gb = Data("dir-card-body".utf8)
    write(g, gb)
    try! fm.createDirectory(atPath: indexDir + "/" + sha(gb) + ".html", withIntermediateDirectories: true)
    check(idx.preview(forPath: g).outcome == .notChecked(.invalidEntry), "directory entry")

    let h = files + "/fifo-card"
    let hb = Data("fifo-card-body".utf8)
    write(h, hb)
    precondition(mkfifo(indexDir + "/" + sha(hb) + ".html", 0o644) == 0)
    check(idx.preview(forPath: h).outcome == .notChecked(.invalidEntry), "FIFO entry does not hang")

    // A FIFO as the previewed file itself is not opened.
    precondition(mkfifo(files + "/fifo", 0o644) == 0)
    check(idx.preview(forPath: files + "/fifo").outcome == .notChecked(.unreadable), "FIFO file")
}

// 6. Symlinked index entry: refused even though the target is a valid card.
do {
    let f = files + "/linked"
    let body = Data("linked-body".utf8)
    write(f, body)
    let target = base + "/elsewhere.html"
    write(target, card("elsewhere"))
    try! fm.createSymbolicLink(atPath: indexDir + "/" + sha(body) + ".html", withDestinationPath: target)
    let r = idx.preview(forPath: f)
    check(r.outcome == .notChecked(.invalidEntry), "symlinked entry: \(r.outcome)")
    check(!html(r).contains("card elsewhere"), "symlink target not shown")

    // The previewed file itself may be a symlink (Go's os.Stat follows it).
    try! fm.createSymbolicLink(atPath: files + "/alias", withDestinationPath: files + "/tool")
    check(idx.preview(forPath: files + "/alias").outcome == .indexed(sha256: sha(Data("pointer-hit".utf8)), via: .hash), "symlinked file is followed")
}

// 7. Large files: no hashing without a pointer; a pointer still works.
do {
    var small = idx
    small.maxHashBytes = 1024
    let f = files + "/huge.dmg"
    write(f, Data(repeating: 0, count: 2048))
    addEntry(sha(Data(repeating: 0, count: 2048)), card("huge"))
    check(small.preview(forPath: f).outcome == .notChecked(.tooLarge), "too large without pointer")
    let st = BinchkIndex.statRegular(f)!
    addPointer(path: f, digest: sha(Data(repeating: 0, count: 2048)), size: st.size, mtimeNs: st.mtimeNs)
    check(small.preview(forPath: f).outcome == .indexed(sha256: sha(Data(repeating: 0, count: 2048)), via: .pointer), "too large with pointer")

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
}

// 9. Normalisation.
check(BinchkIndex.normalize("/a/b/") == "/a/b", "trailing slash")
check(BinchkIndex.normalize("/a/./b/../c") == "/a/c", "dot segments")
check(BinchkIndex.normalize("/") == "/", "root")
check(BinchkIndex.isDigest(String(repeating: "0", count: 64)), "digest ok")
check(!BinchkIndex.isDigest(String(repeating: "0", count: 63)), "short digest")
check(!BinchkIndex.isDigest(String(repeating: "g", count: 64)), "non-hex digest")

// 10. Default index dir is the real home, not a container.
check(BinchkIndex.defaultIndexDir().hasSuffix("/Library/Application Support/binchk/index"), "default index dir")
check(!BinchkIndex.defaultIndexDir().contains("/Library/Containers/"), "default index dir outside containers")

if failures == 0 { try? fm.removeItem(atPath: base) } else { print("left fixtures in \(base)") }
print("\(checks - failures)/\(checks) checks passed")
exit(failures == 0 ? 0 : 1)
