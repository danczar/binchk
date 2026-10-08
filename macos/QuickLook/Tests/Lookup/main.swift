// Command-line lookup through BinchkIndex, for tests that join an index
// written by binchk with the preview's reader.
// usage: lookup INDEX_DIR PATH...
// Prints one JSON object per path: {"path", "outcome", "html"}.

import Foundation

let args = CommandLine.arguments
guard args.count >= 3 else {
    FileHandle.standardError.write(Data("usage: lookup INDEX_DIR PATH...\n".utf8))
    exit(2)
}
let index = BinchkIndex(indexDir: args[1])
for path in args[2...] {
    let r = index.preview(forPath: path)
    let obj: [String: String] = [
        "path": path,
        "outcome": String(describing: r.outcome),
        "html": String(decoding: r.html, as: UTF8.self),
    ]
    let line = try! JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
    FileHandle.standardOutput.write(line + Data("\n".utf8))
}
