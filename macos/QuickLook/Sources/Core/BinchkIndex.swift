// Index lookup for the binchk Quick Look preview.
//
// binchk writes a report index next to its reports (schema version 2):
//
//   <data>/index/entries/<id>.html   ready-to-display card
//   <data>/index/entries/<id>.json   condensed result
//   <data>/index/paths/<p>.json      the entry last recorded for a path, with
//                                    the item's state at the time
//   <data>/index/content/<k>.json    the latest analysis of content k
//
// <p> is the SHA-256 of the UTF-8 absolute path. <k> is the item's content
// key: a file's SHA-256, or an app bundle's fingerprint (see
// bundleFingerprint; binchk's internal/bundleid computes the same value).
// <id> names one analysis of one item at one path.
//
// A fresh path pointer leads straight to the item's own card. Otherwise the
// content key is computed and the content map gives the most recent
// analysis of the same content, shown under a "Not checked at this
// location" banner that names that analysis. For an app the key covers only
// file names and sizes, and the banner says so.
//
// This file is pure Foundation + CryptoKit so the command-line harness in
// ../../Tests can exercise it outside the sandbox.

import CryptoKit
import Darwin
import Foundation

/// Why there is no card to show for an item.
enum NotCheckedReason: Error, Equatable, Sendable {
    /// binchk has not recorded a result for this content.
    case noEntry
    /// The item is too big to look up quickly and no path pointer matched.
    case tooLarge
    /// The item (or a bundle's main executable) could not be read, or the
    /// bundle has no valid main executable.
    case unreadable
    /// An index entry exists but is not a plain, reasonably sized file.
    case invalidEntry
}

/// What kind of item is previewed. An entry of another kind is never shown.
enum ItemKind: String, Equatable, Sendable {
    case file
    case bundle
}

/// How the entry was found.
enum KeySource: Equatable, Sendable {
    /// Through the item's own path pointer.
    case pointer
    /// Through its content key: the most recent analysis of the same
    /// content, at `path` on `analyzedAt` (RFC 3339). For an app (`bundle`)
    /// the key only covers file names and sizes, not their contents.
    case content(path: String, analyzedAt: String, bundle: Bool)
}

enum PreviewOutcome: Equatable, Sendable {
    case indexed(entry: String, via: KeySource)
    case notChecked(NotCheckedReason)
}

struct PreviewResult: Sendable {
    let outcome: PreviewOutcome
    /// UTF-8 HTML to hand to Quick Look.
    let html: Data
}

struct BinchkIndex: Sendable {
    static let schemaVersion = 2
    /// Largest card the preview will load.
    static let defaultMaxEntryBytes = 512 * 1024
    /// Largest entry JSON, pointer or content map the preview will read.
    static let maxJSONBytes = 256 * 1024
    /// Largest Info.plist read for a bundle (binchk uses the same limit).
    static let maxInfoPlistBytes = 1 << 20
    /// Files above this size are only looked up through a pointer: hashing
    /// them would keep the preview spinning for seconds.
    static let defaultMaxHashBytes: Int64 = 1 << 30
    /// Bundles with more entries than this, or whose walk takes longer than
    /// the budget, are not looked up.
    static let defaultMaxWalkEntries = 200_000
    static let defaultWalkBudget: TimeInterval = 3

    let indexDir: String
    var maxEntryBytes = BinchkIndex.defaultMaxEntryBytes
    var maxHashBytes = BinchkIndex.defaultMaxHashBytes
    var maxWalkEntries = BinchkIndex.defaultMaxWalkEntries
    var walkBudget = BinchkIndex.defaultWalkBudget

    init(indexDir: String) {
        self.indexDir = indexDir
    }

    /// The index of the logged-in user's binchk data directory. Inside the
    /// app sandbox NSHomeDirectory() is the container, so the real home comes
    /// from the password database.
    static func defaultIndexDir() -> String {
        var home: String?
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
            home = String(cString: dir)
        }
        let base = home ?? NSHomeDirectoryForUser(NSUserName()) ?? NSHomeDirectory()
        return base + "/Library/Application Support/binchk/index"
    }

    /// Resolves path to its index entry and returns the HTML to display:
    /// the stored card (with a banner when matched by contents), or a
    /// built-in "Not checked by binchk" card.
    func preview(forPath rawPath: String) -> PreviewResult {
        let path = Self.normalize(rawPath)
        let name = (path as NSString).lastPathComponent
        let outcome = resolve(path)
        switch outcome {
        case .indexed(let id, let via):
            switch loadCard(entry: id) {
            case .success(var data):
                if case .content(let p, let at, let bundle) = via {
                    data = Self.injectBanner(data, banner: Self.banner(analysedPath: p, analyzedAt: at, bundle: bundle))
                }
                return PreviewResult(outcome: outcome, html: data)
            case .failure(let reason):
                return PreviewResult(outcome: .notChecked(reason), html: Self.notCheckedCard(fileName: name, reason: reason))
            }
        case .notChecked(let reason):
            return PreviewResult(outcome: outcome, html: Self.notCheckedCard(fileName: name, reason: reason))
        }
    }

    // MARK: - Items

    /// The previewed item as binchk identifies it.
    struct Item {
        let kind: ItemKind
        let path: String
        /// File: the file's state. Bundle: its main executable's.
        let stat: FileStat
        /// Bundle only: the main executable and the resolved bundle root.
        let executable: String?
        let root: String?
    }

    /// Classifies path: a regular file (symlinks followed, as binchk's
    /// os.Stat does), or an .app directory with a valid main executable.
    static func item(at path: String) -> Item? {
        var st = stat()
        guard stat(path, &st) == 0 else { return nil }
        switch st.st_mode & S_IFMT {
        case S_IFREG:
            guard let fs = statRegular(path) else { return nil }
            return Item(kind: .file, path: path, stat: fs, executable: nil, root: nil)
        case S_IFDIR:
            guard let exe = mainExecutable(forBundle: path), let fs = statRegular(exe),
                  let real = realpath(path, nil) else { return nil }
            defer { free(real) }
            return Item(kind: .bundle, path: path, stat: fs, executable: exe, root: String(cString: real))
        default:
            return nil
        }
    }

    /// The main executable of an application bundle, Contents/MacOS/ +
    /// CFBundleExecutable, or nil when the bundle has none: not an .app, no
    /// regular Info.plist, or a CFBundleExecutable that is empty, ".", ".."
    /// or contains "/" (binchk refuses the same names).
    static func mainExecutable(forBundle path: String) -> String? {
        guard (path as NSString).pathExtension.lowercased() == "app" else { return nil }
        guard let data = readRegular(path + "/Contents/Info.plist", max: maxInfoPlistBytes),
              let obj = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dict = obj as? [String: Any],
              let exe = dict["CFBundleExecutable"] as? String,
              validExecutableName(exe)
        else { return nil }
        return path + "/Contents/MacOS/" + exe
    }

    static func validExecutableName(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && !name.contains("/") && !name.contains("\0")
    }

    // MARK: - Resolution

    /// Finds the entry for path: through a fresh path pointer if there is
    /// one, otherwise through its content key. The card may still be absent.
    func resolve(_ path: String) -> PreviewOutcome {
        guard let item = Self.item(at: path) else {
            return .notChecked(.unreadable)
        }
        var candidates = [path]
        if let real = realpath(path, nil) {
            let r = String(cString: real)
            free(real)
            if r != path { candidates.append(r) }
        }
        // A bundle's walk serves both the pointer check and the fingerprint.
        var walked: Walk??
        func walk() -> Walk? {
            if case .some(let w) = walked { return w }
            let w = Self.walk(root: item.root!, maxEntries: maxWalkEntries, budget: walkBudget)
            walked = .some(w)
            return w
        }
        for p in candidates {
            guard let ptr = pointer(forPath: p), ptr.kind == item.kind.rawValue else { continue }
            let fresh: Bool
            switch item.kind {
            case .file:
                fresh = ptr.size == item.stat.size && ptr.mtime_unix_ns == item.stat.mtimeNs
            case .bundle:
                fresh = ptr.exec_size == item.stat.size && ptr.exec_mtime_unix_ns == item.stat.mtimeNs
                    && walk().map { ptr.tree_entries == $0.tree.entries && ptr.tree_size == $0.tree.size
                        && ptr.tree_mtime_unix_ns == $0.tree.mtimeNs } == true
            }
            if fresh, let head = entryHead(ptr.entry), head.kind == item.kind.rawValue, cardExists(ptr.entry) {
                return .indexed(entry: ptr.entry, via: .pointer)
            }
        }
        // Without an index nothing can match, so don't read the item.
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: indexDir, isDirectory: &isDir), isDir.boolValue else {
            return .notChecked(.noEntry)
        }
        if item.stat.size > maxHashBytes {
            return .notChecked(.tooLarge)
        }
        let key: String
        switch item.kind {
        case .file:
            guard let k = Self.sha256File(item.path) else { return .notChecked(.unreadable) }
            key = k
        case .bundle:
            guard let w = walk() else { return .notChecked(.tooLarge) }
            guard let main = Self.sha256File(item.executable!),
                  let k = Self.bundleFingerprint(root: item.root!, mainSHA256: main, manifest: w.manifest)
            else { return .notChecked(.unreadable) }
            key = k
        }
        guard let ref = contentRef(key),
              let head = entryHead(ref.entry),
              head.kind == item.kind.rawValue, head.content_key == key,
              cardExists(ref.entry)
        else { return .notChecked(.noEntry) }
        return .indexed(entry: ref.entry, via: .content(path: ref.path, analyzedAt: ref.analyzed_at, bundle: item.kind == .bundle))
    }

    /// Absolute, with "." and ".." removed and no trailing slash, the way
    /// binchk records analysed paths. Symlinks are not resolved here.
    static func normalize(_ path: String) -> String {
        var p = URL(fileURLWithPath: path).standardizedFileURL.path
        while p.count > 1 && p.hasSuffix("/") { p.removeLast() }
        return p
    }

    struct Pointer: Decodable {
        let version: Int
        let entry: String
        let kind: String
        let size: Int64?
        let mtime_unix_ns: Int64?
        let tree_entries: Int64?
        let tree_size: Int64?
        let tree_mtime_unix_ns: Int64?
        let exec_size: Int64?
        let exec_mtime_unix_ns: Int64?
    }

    private struct EntryHead: Decodable {
        let version: Int
        let entry_id: String
        let content_key: String
        let kind: String
    }

    private struct ContentRef: Decodable {
        let version: Int
        let entry: String
        let path: String
        let analyzed_at: String
    }

    private func readJSON<T: Decodable>(_ type: T.Type, _ path: String) -> T? {
        guard let data = Self.readRegular(path, max: Self.maxJSONBytes) else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }

    /// The pointer for path, if it exists and is well formed. Whether it is
    /// still fresh is up to the caller.
    func pointer(forPath path: String) -> Pointer? {
        let key = Self.hex(SHA256.hash(data: Data(path.utf8)))
        guard let p = readJSON(Pointer.self, indexDir + "/paths/" + key + ".json"),
              p.version == Self.schemaVersion, Self.isDigest(p.entry)
        else { return nil }
        return p
    }

    private func contentRef(_ key: String) -> ContentRef? {
        guard Self.isDigest(key),
              let c = readJSON(ContentRef.self, indexDir + "/content/" + key + ".json"),
              c.version == Self.schemaVersion, Self.isDigest(c.entry)
        else { return nil }
        return c
    }

    private func entryHead(_ id: String) -> EntryHead? {
        guard Self.isDigest(id),
              let e = readJSON(EntryHead.self, indexDir + "/entries/" + id + ".json"),
              e.version == Self.schemaVersion, e.entry_id == id
        else { return nil }
        return e
    }

    // MARK: - Cards

    private func cardPath(_ id: String) -> String {
        indexDir + "/entries/" + id + ".html"
    }

    private func cardExists(_ id: String) -> Bool {
        var st = stat()
        return Self.isDigest(id) && lstat(cardPath(id), &st) == 0
    }

    func loadCard(entry id: String) -> Result<Data, NotCheckedReason> {
        guard Self.isDigest(id) else { return .failure(.invalidEntry) }
        let p = cardPath(id)
        var st = stat()
        guard lstat(p, &st) == 0 else { return .failure(.noEntry) }
        guard let data = Self.readRegular(p, max: maxEntryBytes), !data.isEmpty else {
            return .failure(.invalidEntry)
        }
        return .success(data)
    }

    /// The banner shown above a card found by content: where and when that
    /// content was analysed, and how strong the match is. A file matched by
    /// its SHA-256 has the same contents; an app matched by its fingerprint
    /// only has the same file names and sizes, so the banner says the card
    /// belongs to another copy. Everything in it is escaped.
    static func banner(analysedPath: String, analyzedAt: String, bundle: Bool = false) -> String {
        let name = (analysedPath as NSString).lastPathComponent
        let folder = (analysedPath as NSString).deletingLastPathComponent
        var when = analyzedAt
        if let date = ISO8601DateFormatter().date(from: analyzedAt) {
            let f = DateFormatter()
            f.locale = Locale(identifier: "en_US_POSIX")
            f.dateFormat = "d MMM yyyy, HH:mm"
            when = f.string(from: date)
        }
        if bundle {
            return "<div class=\"match\">Not checked at this location. This is the report for another copy, <b>\(escape(name))</b> in \(escape(folder)) (\(escape(when))), with the same file names and sizes; file contents were not compared. Run binchk scan on this app to check it.</div>"
        }
        return "<div class=\"match\">Not checked at this location. Same contents as <b>\(escape(name))</b>, checked in \(escape(folder)) on \(escape(when)).</div>"
    }

    /// Puts banner at the top of the card.
    static func injectBanner(_ card: Data, banner: String) -> Data {
        var html = String(decoding: card, as: UTF8.self)
        if let r = html.range(of: "<div class=\"card\">") {
            html.insert(contentsOf: banner, at: r.upperBound)
        } else if let r = html.range(of: "<body"), let close = html[r.upperBound...].firstIndex(of: ">") {
            html.insert(contentsOf: banner, at: html.index(after: close))
        } else {
            html = banner + html
        }
        return Data(html.utf8)
    }

    // MARK: - Bundle fingerprint

    struct Tree: Equatable {
        var entries: Int64 = 0
        var size: Int64 = 0
        var mtimeNs: Int64 = 0
    }

    struct ManifestEntry {
        let path: [UInt8]
        let type: UInt8
        let value: [UInt8]
    }

    struct Walk {
        let tree: Tree
        let manifest: [ManifestEntry]
    }

    /// Walks root without following symbolic links: the tree summary (root
    /// included) and the sorted manifest (root excluded). nil when an entry
    /// cannot be read, or the walk exceeds maxEntries or budget seconds.
    static func walk(root: String, maxEntries: Int, budget: TimeInterval) -> Walk? {
        let rootBytes = Array(root.utf8)
        let deadline = Date().addingTimeInterval(budget)
        var tree = Tree()
        var manifest: [ManifestEntry] = []
        func account(_ st: stat) -> Bool {
            tree.entries += 1
            tree.size += Int64(st.st_size)
            let ns = Int64(st.st_mtimespec.tv_sec).multipliedReportingOverflow(by: 1_000_000_000)
            guard !ns.overflow else { return false }
            tree.mtimeNs = max(tree.mtimeNs, ns.partialValue + Int64(st.st_mtimespec.tv_nsec))
            return true
        }
        var st = stat()
        guard withCPath(rootBytes, { lstat($0, &st) }) == 0, st.st_mode & S_IFMT == S_IFDIR, account(st) else { return nil }
        var dirs: [[UInt8]] = [[]]
        while let rel = dirs.popLast() {
            let dirPath = rel.isEmpty ? rootBytes : rootBytes + [0x2f] + rel
            guard let d = withCPath(dirPath, { opendir($0) }) else { return nil }
            defer { closedir(d) }
            while let ent = readdir(d) {
                let name = withUnsafeBytes(of: ent.pointee.d_name) { Array($0.prefix(Int(ent.pointee.d_namlen))) }
                if name == [0x2e] || name == [0x2e, 0x2e] { continue }
                let childRel = rel.isEmpty ? name : rel + [0x2f] + name
                let childPath = rootBytes + [0x2f] + childRel
                guard withCPath(childPath, { lstat($0, &st) }) == 0, account(st) else { return nil }
                if tree.entries > Int64(maxEntries) { return nil }
                if tree.entries % 1024 == 0 && Date() > deadline { return nil }
                switch st.st_mode & S_IFMT {
                case S_IFDIR:
                    dirs.append(childRel)
                    manifest.append(ManifestEntry(path: childRel, type: UInt8(ascii: "d"), value: []))
                case S_IFLNK:
                    guard let target = readLink(childPath) else { return nil }
                    manifest.append(ManifestEntry(path: childRel, type: UInt8(ascii: "l"), value: target))
                case S_IFREG:
                    manifest.append(ManifestEntry(path: childRel, type: UInt8(ascii: "f"), value: Array(String(st.st_size).utf8)))
                default:
                    manifest.append(ManifestEntry(path: childRel, type: UInt8(ascii: "o"), value: []))
                }
            }
        }
        manifest.sort { $0.path.lexicographicallyPrecedes($1.path) }
        return Walk(tree: tree, manifest: manifest)
    }

    /// The bundle fingerprint (binchk's internal/bundleid):
    ///
    ///   SHA-256( str(domain) str(main) str(seal) u64(n) { str(path) str(type) str(value) } )
    ///
    /// with str(s) = u64(len(s)) ‖ s and u64 big-endian. main is the main
    /// executable's SHA-256 (hex), seal the SHA-256 of a regular
    /// Contents/_CodeSignature/CodeResources (or "none").
    static func bundleFingerprint(root: String, mainSHA256: String, manifest: [ManifestEntry]) -> String? {
        let sealPath = root + "/Contents/_CodeSignature/CodeResources"
        var seal = "none"
        var st = stat()
        if lstat(sealPath, &st) == 0 && st.st_mode & S_IFMT == S_IFREG {
            guard let h = sha256File(sealPath, followLinks: false) else { return nil }
            seal = h
        }
        var hasher = SHA256()
        func u64(_ v: Int) {
            var be = UInt64(v).bigEndian
            withUnsafeBytes(of: &be) { hasher.update(bufferPointer: $0) }
        }
        func str(_ b: [UInt8]) {
            u64(b.count)
            hasher.update(data: b)
        }
        str(Array("binchk bundle fingerprint v2".utf8))
        str(Array(mainSHA256.utf8))
        str(Array(seal.utf8))
        u64(manifest.count)
        for e in manifest {
            str(e.path)
            str([e.type])
            str(e.value)
        }
        return hex(hasher.finalize())
    }

    private static func withCPath<R>(_ bytes: [UInt8], _ body: (UnsafePointer<CChar>) -> R) -> R {
        let c = bytes.map { CChar(bitPattern: $0) } + [0]
        return c.withUnsafeBufferPointer { body($0.baseAddress!) }
    }

    private static func readLink(_ path: [UInt8]) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: Int(PATH_MAX) + 1)
        let n = withCPath(path) { p in
            buf.withUnsafeMutableBufferPointer { readlink(p, UnsafeMutableRawPointer($0.baseAddress!).assumingMemoryBound(to: CChar.self), $0.count) }
        }
        guard n >= 0 else { return nil }
        return Array(buf[0..<n])
    }

    // MARK: - File helpers

    static func isDigest(_ s: String) -> Bool {
        s.utf8.count == 64 && s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        let digits = Array("0123456789abcdef".utf8)
        var out = [UInt8]()
        out.reserveCapacity(64)
        for b in digest {
            out.append(digits[Int(b >> 4)])
            out.append(digits[Int(b & 0xf)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    struct FileStat {
        let size: Int64
        let mtimeNs: Int64
    }

    /// stat(2) that follows symlinks (as Go's os.Stat does) and accepts only
    /// regular files.
    static func statRegular(_ path: String) -> FileStat? {
        var st = stat()
        guard stat(path, &st) == 0, st.st_mode & S_IFMT == S_IFREG else { return nil }
        let ns = Int64(st.st_mtimespec.tv_sec).multipliedReportingOverflow(by: 1_000_000_000)
        guard !ns.overflow else { return nil }
        return FileStat(size: Int64(st.st_size), mtimeNs: ns.partialValue + Int64(st.st_mtimespec.tv_nsec))
    }

    /// Reads a regular file of at most max bytes. The final path component
    /// must not be a symlink, and FIFOs or devices are never opened for
    /// reading (O_NONBLOCK keeps open from waiting on a FIFO).
    static func readRegular(_ path: String, max: Int) -> Data? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_size <= Int64(max) else { return nil }
        var data = Data(count: max + 1)
        var total = 0
        let ok = data.withUnsafeMutableBytes { (buf: UnsafeMutableRawBufferPointer) -> Bool in
            while total <= max {
                let n = read(fd, buf.baseAddress! + total, max + 1 - total)
                if n < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                if n == 0 { break }
                total += n
            }
            return true
        }
        guard ok, total <= max else { return nil }
        data.count = total
        return data
    }

    /// Streaming SHA-256 of a regular file, lowercase hex. followLinks:
    /// false refuses a symlink as the final component.
    static func sha256File(_ path: String, followLinks: Bool = true) -> String? {
        let fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | (followLinks ? 0 : O_NOFOLLOW))
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG else { return nil }
        var hasher = SHA256()
        let chunk = 1 << 20
        let buf = UnsafeMutableRawBufferPointer.allocate(byteCount: chunk, alignment: 16)
        defer { buf.deallocate() }
        while true {
            let n = read(fd, buf.baseAddress!, chunk)
            if n < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if n == 0 { break }
            hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: buf[0..<n]))
        }
        return hex(hasher.finalize())
    }

    // MARK: - Built-in card

    static func escape(_ s: String) -> String {
        var out = ""
        out.reserveCapacity(s.count)
        for c in s {
            switch c {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            case "'": out += "&#39;"
            default: out.append(c)
            }
        }
        return out
    }

    /// The card shown when binchk has no result for an item. Same palette as
    /// binchk's reports; inline CSS only.
    static func notCheckedCard(fileName: String, reason: NotCheckedReason) -> Data {
        let detail: String
        switch reason {
        case .noEntry:
            detail = "binchk checks new downloads automatically; run <code>binchk scan &lt;file&gt;</code> to check this one."
        case .tooLarge:
            detail = "This item is too large to look up quickly. Run <code>binchk scan &lt;file&gt;</code> to check it."
        case .unreadable:
            detail = "The preview could not read this item. Run <code>binchk scan &lt;file&gt;</code> to check it."
        case .invalidEntry:
            detail = "binchk&#39;s stored result for this item could not be loaded. Run <code>binchk scan &lt;file&gt;</code> to check it again."
        }
        let html = """
        <!doctype html>
        <html lang="en"><head><meta charset="utf-8">
        <meta name="color-scheme" content="light dark">
        <title>binchk</title>
        <style>
        :root{--bg:#f6f7f9;--panel:#fff;--ink:#16181d;--muted:#5f6673;--line:#e3e6eb;--code:#f0f2f5;--accent:#6b7280}
        @media (prefers-color-scheme:dark){:root{--bg:#0f1115;--panel:#171a21;--ink:#e7e9ee;--muted:#9aa3b2;--line:#262b35;--code:#1e222b;--accent:#9aa3b2}}
        *{box-sizing:border-box}
        html,body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
        main{max-width:640px;margin:0 auto;padding:20px 16px}
        .panel{background:var(--panel);border:1px solid var(--line);border-top:5px solid var(--accent);border-radius:10px;padding:16px 18px}
        .brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:0 0 6px}
        h1{margin:0 0 8px;font-size:19px;word-break:break-all}
        .verdict{display:inline-block;background:var(--accent);color:#fff;font-weight:700;padding:2px 11px;border-radius:999px;font-size:12.5px;letter-spacing:.03em}
        @media (prefers-color-scheme:dark){.verdict{color:#0f1115}}
        p{margin:10px 0 0;color:var(--muted)}
        code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;background:var(--code);border:1px solid var(--line);border-radius:5px;padding:0 5px;color:var(--ink)}
        </style></head>
        <body><main><div class="panel">
        <p class="brand">binchk</p>
        <h1>\(escape(fileName))</h1>
        <span class="verdict">Not checked by binchk</span>
        <p>\(detail)</p>
        </div></main></body></html>
        """
        return Data(html.utf8)
    }
}
