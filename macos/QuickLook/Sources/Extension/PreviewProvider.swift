// Quick Look preview extension: shows binchk's verdict card for a file.

import Foundation
import QuickLookUI
import UniformTypeIdentifiers

@objc(BinchkPreviewProvider)
final class PreviewProvider: QLPreviewProvider, QLPreviewingController {
    func providePreview(for request: QLFilePreviewRequest) async throws -> QLPreviewReply {
        let path = request.fileURL.path
        let index = BinchkIndex(indexDir: BinchkIndex.defaultIndexDir())
        return QLPreviewReply(dataOfContentType: .html, contentSize: CGSize(width: 680, height: 480)) { _ in
            index.preview(forPath: path).html
        }
    }
}
