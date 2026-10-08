// Index lookup for the binchk Quick Look preview.
//
// binchk writes a content-addressed index next to its reports:
//
//   <data>/index/<sha256>.html        ready-to-display card
//   <data>/index/<sha256>.json        condensed result
//   <data>/index/paths/<p>.json       {"sha256", "size", "mtime_unix_ns"}
//
// where <sha256> is the SHA-256 of the analysed file (for an .app bundle, of
// its main executable) and <p> is the SHA-256 of the UTF-8 absolute path that
// was analysed. This file is pure Foundation + CryptoKit so the command-line
// harness in ../../Tests can exercise it outside the sandbox.

import CryptoKit
import Darwin
import Foundation

/// Why there is no card to show for a file.
enum NotCheckedReason: Error, Equatable, Sendable {
    /// binchk has not recorded a result for these bytes.
    case noEntry
    /// The file is too big to hash quickly and no path pointer matched.
    case tooLarge
    /// The file (or the bundle's main executable) could not be read.
    case unreadable
    /// An index entry exists but is not a plain, reasonably sized file.
    case invalidEntry
}

/// How the index key was found.
enum KeySource: Equatable, Sendable {
    case pointer
    case hash
}

enum PreviewOutcome: Equatable, Sendable {
    case indexed(sha256: String, via: KeySource)
    case notChecked(NotCheckedReason)
}

struct PreviewResult: Sendable {
    let outcome: PreviewOutcome
    /// UTF-8 HTML to hand to Quick Look.
    let html: Data
}

struct BinchkIndex: Sendable {
    /// Largest card the preview will load.
    static let defaultMaxEntryBytes = 512 * 1024
    /// Pointers are a few dozen bytes; anything bigger is not one.
    static let maxPointerBytes = 4 * 1024
    /// Files above this size are only looked up through a pointer: hashing
    /// them would keep the preview spinning for seconds.
    static let defaultMaxHashBytes: Int64 = 1 << 30

    let indexDir: String
    var maxEntryBytes = BinchkIndex.defaultMaxEntryBytes
    var maxHashBytes = BinchkIndex.defaultMaxHashBytes

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
    /// the stored card, or a built-in "Not checked by binchk" card.
    func preview(forPath rawPath: String) -> PreviewResult {
        let path = Self.normalize(rawPath)
        let name = (path as NSString).lastPathComponent
        let outcome = resolve(path)
        switch outcome {
        case .indexed(let sha, _):
            switch loadEntry(sha256: sha) {
            case .success(let data):
                return PreviewResult(outcome: outcome, html: data)
            case .failure(let reason):
                return PreviewResult(outcome: .notChecked(reason), html: Self.notCheckedCard(fileName: name, reason: reason))
            }
        case .notChecked(let reason):
            return PreviewResult(outcome: outcome, html: Self.notCheckedCard(fileName: name, reason: reason))
        }
    }

    // MARK: - Key resolution

    /// Finds the index key for path: through a fresh path pointer if there
    /// is one, otherwise by hashing. The returned entry may still be absent.
    func resolve(_ path: String) -> PreviewOutcome {
        guard let target = Self.hashTarget(for: path), let st = Self.statRegular(target) else {
            return .notChecked(.unreadable)
        }
        var candidates = [path]
        if let real = realpath(path, nil) {
            let r = String(cString: real)
            free(real)
            if r != path { candidates.append(r) }
        }
        for p in candidates {
            if let sha = pointer(forPath: p, size: st.size, mtimeNs: st.mtimeNs), entryExists(sha256: sha) {
                return .indexed(sha256: sha, via: .pointer)
            }
        }
        // Without an index nothing can match, so don't read the whole file.
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: indexDir, isDirectory: &isDir), isDir.boolValue else {
            return .notChecked(.noEntry)
        }
        if st.size > maxHashBytes {
            return .notChecked(.tooLarge)
        }
        guard let sha = Self.sha256File(target) else {
            return .notChecked(.unreadable)
        }
        guard entryExists(sha256: sha) else {
            return .notChecked(.noEntry)
        }
        return .indexed(sha256: sha, via: .hash)
    }

    /// The file whose bytes key the index: path itself, or the main
    /// executable of an application bundle (Contents/MacOS/CFBundleExecutable,
    /// exactly as binchk computes it).
    static func hashTarget(for path: String) -> String? {
        var st = stat()
        guard stat(path, &st) == 0 else { return nil }
        if st.st_mode & S_IFMT != S_IFDIR {
            return path
        }
        guard (path as NSString).pathExtension.lowercased() == "app" else { return nil }
        let plist = path + "/Contents/Info.plist"
        guard let data = readRegular(plist, max: 1 << 20),
              let obj = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dict = obj as? [String: Any],
              let exe = dict["CFBundleExecutable"] as? String,
              !exe.isEmpty, exe != ".", exe != "..", !exe.contains("/"), !exe.contains("\0")
        else { return nil }
        return path + "/Contents/MacOS/" + exe
    }

    /// Absolute, with "." and ".." removed and no trailing slash, the way
    /// binchk records analysed paths. Symlinks are not resolved here.
    static func normalize(_ path: String) -> String {
        var p = URL(fileURLWithPath: path).standardizedFileURL.path
        while p.count > 1 && p.hasSuffix("/") { p.removeLast() }
        return p
    }

    private struct Pointer: Decodable {
        let sha256: String
        let size: Int64
        let mtime_unix_ns: Int64
    }

    /// The digest a path pointer records for path, if the pointer exists, is
    /// well formed and still matches the file's size and mtime.
    func pointer(forPath path: String, size: Int64, mtimeNs: Int64) -> String? {
        let key = Self.hex(SHA256.hash(data: Data(path.utf8)))
        guard let data = Self.readRegular(indexDir + "/paths/" + key + ".json", max: Self.maxPointerBytes),
              let p = try? JSONDecoder().decode(Pointer.self, from: data),
              Self.isDigest(p.sha256), p.size == size, p.mtime_unix_ns == mtimeNs
        else { return nil }
        return p.sha256
    }

    // MARK: - Entries

    private func entryPath(_ sha256: String) -> String {
        indexDir + "/" + sha256 + ".html"
    }

    private func entryExists(sha256: String) -> Bool {
        var st = stat()
        return Self.isDigest(sha256) && lstat(entryPath(sha256), &st) == 0
    }

    func loadEntry(sha256: String) -> Result<Data, NotCheckedReason> {
        guard Self.isDigest(sha256) else { return .failure(.invalidEntry) }
        let p = entryPath(sha256)
        var st = stat()
        guard lstat(p, &st) == 0 else { return .failure(.noEntry) }
        guard let data = Self.readRegular(p, max: maxEntryBytes), !data.isEmpty else {
            return .failure(.invalidEntry)
        }
        return .success(data)
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

    /// Streaming SHA-256 of a regular file, lowercase hex.
    static func sha256File(_ path: String) -> String? {
        let fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
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

    /// The card shown when binchk has no result for a file. Same palette as
    /// binchk's reports; inline CSS only.
    static func notCheckedCard(fileName: String, reason: NotCheckedReason) -> Data {
        let detail: String
        switch reason {
        case .noEntry:
            detail = "binchk checks new downloads automatically; run <code>binchk scan &lt;file&gt;</code> to check this one."
        case .tooLarge:
            detail = "This file is too large to look up quickly. Run <code>binchk scan &lt;file&gt;</code> to check it."
        case .unreadable:
            detail = "The preview could not read this item. Run <code>binchk scan &lt;file&gt;</code> to check it."
        case .invalidEntry:
            detail = "binchk&#39;s stored result for this file could not be loaded. Run <code>binchk scan &lt;file&gt;</code> to check it again."
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
