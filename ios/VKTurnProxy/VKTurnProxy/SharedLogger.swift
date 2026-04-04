import Foundation

/// Shared file logger for VPN logs.
/// Both the main app and the Network Extension write to the same file
/// in the App Group container, so logs can be viewed in-app or exported.
class SharedLogger {
    static let shared = SharedLogger()

    private let fileURL: URL?
    private let queue = DispatchQueue(label: "com.vkturnproxy.logger", qos: .utility)
    private let maxFileSize = 5 * 1024 * 1024 // 5 MB
    private let dateFormatter: DateFormatter

    private init() {
        dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")

        if let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.vkturnproxy.app"
        ) {
            fileURL = container.appendingPathComponent("vpn.log")
        } else {
            fileURL = nil
        }
    }

    /// Append a timestamped log line to the shared log file.
    func log(_ message: String) {
        guard let url = fileURL else { return }
        let ts = dateFormatter.string(from: Date())
        let line = "[\(ts)] \(message)\n"
        queue.async { [self] in
            appendData(line.data(using: .utf8)!, to: url)
        }
    }

    /// Append raw data (used by Go bridge for already-timestamped log lines).
    func logRaw(_ data: Data) {
        guard let url = fileURL else { return }
        queue.async { [self] in
            appendData(data, to: url)
        }
    }

    /// Read the entire log file contents.
    func readLogs() -> String {
        guard let url = fileURL else { return "" }
        return (try? String(contentsOf: url, encoding: .utf8)) ?? ""
    }

    /// Delete all log contents.
    func clearLogs() {
        guard let url = fileURL else { return }
        queue.async {
            try? Data().write(to: url)
        }
    }

    /// URL of the log file (for sharing via UIActivityViewController).
    var logFileURL: URL? { fileURL }

    /// Absolute path string (for passing to Go bridge).
    var logFilePath: String? { fileURL?.path }

    // MARK: - Private

    private func appendData(_ data: Data, to url: URL) {
        // Create file if it doesn't exist
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }

        // Rotate if too large
        if let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
           let size = attrs[.size] as? Int, size > maxFileSize {
            rotate(at: url)
        }

        guard let handle = FileHandle(forWritingAtPath: url.path) else { return }
        handle.seekToEndOfFile()
        handle.write(data)
        handle.closeFile()
    }

    private func rotate(at url: URL) {
        guard let content = try? String(contentsOf: url, encoding: .utf8) else { return }
        let lines = content.components(separatedBy: "\n")
        let keep = lines.suffix(from: lines.count / 2).joined(separator: "\n")
        try? keep.write(to: url, atomically: true, encoding: .utf8)
    }
}
