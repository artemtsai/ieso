// DemoApp: a small "business-critical" macOS app with fault switches.
// The sensor observes it only from the outside (we pretend we do not own this source).
//
// Faults (buttons, or CLI for automation:  DemoApp --fault <name> [--after <seconds>]):
//   hang        block the main thread for 30 s (simulated deadlock / sync network call on the UI thread)
//   crash       write through a bad pointer -> EXC_BAD_ACCESS / SIGSEGV
//   leak        retain +20 MB/s until quit
//   network     call the backend, log the error, show "Cannot reach server". With
//               --backend URL --backend-ca PEM [--proxy http://host:port] the app pins its backend CA and calls
//               through the proxy (like a corporate laptop); a TLS-inspecting proxy then breaks the pinned chain.
//               Without --backend it calls an unroutable host.
//   permission  read a privacy-protected file, log the error, show "Permission denied"

import AppKit
import os

let appLog = Logger(subsystem: "com.ieso.demoapp", category: "app")
let netLog = Logger(subsystem: "com.ieso.demoapp", category: "network")

/// Pins the backend's own CA (anchor-only trust), like apps that ship their backend certificate.
final class PinnedTrust: NSObject, URLSessionDelegate {
    let anchor: SecCertificate
    var lastFailure: String?
    init(anchor: SecCertificate) { self.anchor = anchor }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil); return
        }
        SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        var error: CFError?
        if SecTrustEvaluateWithError(trust, &error) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            let why = error.map { CFErrorCopyDescription($0) as String } ?? "untrusted certificate"
            lastFailure = "TLS certificate for \(challenge.protectionSpace.host) is not trusted (\(why))"
            netLog.error("TLS trust failure for \(challenge.protectionSpace.host, privacy: .public): \(why, privacy: .public)")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

func argument(_ name: String) -> String? {
    let args = CommandLine.arguments
    guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
    return args[i + 1]
}

func loadCertificate(_ path: String) -> SecCertificate? {
    guard let pem = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
    let b64 = pem.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
    guard let der = Data(base64Encoded: b64) else { return nil }
    return SecCertificateCreateWithData(nil, der as CFData)
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var status: NSTextField!
    var leaked: [Data] = []
    var leakTimer: Timer?
    var heartbeat: Timer?
    var leakBytes = 0

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildWindow()
        appLog.info("DemoApp \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?", privacy: .public) started")
        heartbeat = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { _ in
            appLog.debug("heartbeat: ui ok, leaked=\(self.leakBytes, privacy: .public) bytes")  // visible only when escalated
        }
        scheduleFaultFromArguments()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    // MARK: UI

    private func buildWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 360, height: 300),
                          styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "DemoApp: Business Critical"
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        let faults: [(String, Selector)] = [
            ("Hang main thread (30 s)", #selector(faultHang)),
            ("Crash (EXC_BAD_ACCESS)", #selector(faultCrash)),
            ("Leak memory (+20 MB/s)", #selector(faultLeak)),
            ("Network failure", #selector(faultNetwork)),
            ("Permission denied", #selector(faultPermission)),
        ]
        for (title, action) in faults {
            stack.addArrangedSubview(NSButton(title: title, target: self, action: action))
        }
        status = NSTextField(labelWithString: "Healthy")
        stack.addArrangedSubview(status)
        window.contentView = stack
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func scheduleFaultFromArguments() {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "--fault"), i + 1 < args.count else { return }
        let fault = args[i + 1]
        var delay = 3.0
        if let j = args.firstIndex(of: "--after"), j + 1 < args.count, let d = Double(args[j + 1]) { delay = d }
        appLog.info("fault '\(fault, privacy: .public)' scheduled in \(delay, privacy: .public) s")
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self else { return }
            switch fault {
            case "hang": self.faultHang()
            case "crash": self.faultCrash()
            case "leak": self.faultLeak()
            case "network": self.faultNetwork()
            case "permission": self.faultPermission()
            default: appLog.error("unknown fault '\(fault, privacy: .public)'")
            }
        }
    }

    private func showError(_ title: String, _ detail: String) {
        status.stringValue = title
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = title
        alert.informativeText = detail
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    // MARK: Faults

    @objc func faultHang() {
        appLog.error("syncing ledger on the main thread (this blocks the UI)")
        Thread.sleep(forTimeInterval: 30)  // simulated deadlock / blocking I/O on the main thread
        appLog.info("ledger sync finished")
    }

    @objc func faultCrash() {
        appLog.fault("applying settings from corrupted cache")
        let bad = UnsafeMutablePointer<Int>(bitPattern: 0x8)!
        bad.pointee = 42  // EXC_BAD_ACCESS (SIGSEGV) at 0x8
    }

    @objc func faultLeak() {
        guard leakTimer == nil else { return }
        appLog.error("image cache eviction disabled (leak starts)")
        status.stringValue = "Leaking..."
        leakTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            guard let self else { return }
            self.leaked.append(Data(repeating: 0xAB, count: 2 * 1024 * 1024))  // touched, so it becomes resident
            self.leakBytes += 2 * 1024 * 1024
        }
    }

    @objc func faultNetwork() {
        let url = URL(string: argument("--backend") ?? "https://10.255.255.1/api/v1/health")!
        var request = URLRequest(url: url)
        request.timeoutInterval = 6
        let config = URLSessionConfiguration.ephemeral
        if let proxy = argument("--proxy"), let p = URL(string: proxy), let host = p.host {
            config.connectionProxyDictionary = [
                kCFNetworkProxiesHTTPSEnable as String: 1,
                kCFNetworkProxiesHTTPSProxy as String: host,
                kCFNetworkProxiesHTTPSPort as String: p.port ?? 8080,
                // Corporate gateways proxy everything; CFNetwork would otherwise bypass localhost.
                kCFNetworkProxiesExceptionsList as String: [String](),
                kCFNetworkProxiesExcludeSimpleHostnames as String: 0,
            ]
            netLog.info("using HTTPS proxy \(proxy, privacy: .public)")
        }
        var pinned: PinnedTrust?
        if let caPath = argument("--backend-ca"), let anchor = loadCertificate(caPath) {
            pinned = PinnedTrust(anchor: anchor)
        }
        let delegate: URLSessionDelegate? = pinned
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        netLog.info("calling backend \(url.absoluteString, privacy: .public)")
        session.dataTask(with: request) { data, response, error in
            if error == nil, let http = response as? HTTPURLResponse, http.statusCode == 200 {
                netLog.info("backend sync ok (\(data?.count ?? 0, privacy: .public) bytes)")
                DispatchQueue.main.async { self.status.stringValue = "Synced" }
                return
            }
            let message = pinned?.lastFailure ?? error?.localizedDescription ?? "unexpected response"
            netLog.error("backend unreachable: \(message, privacy: .public)")
            DispatchQueue.main.async { self.showError("Cannot reach server", "Sync failed: \(message)") }
        }.resume()
    }

    @objc func faultPermission() {
        let path = NSHomeDirectory() + "/Library/Messages/chat.db"
        do {
            _ = try Data(contentsOf: URL(fileURLWithPath: path))
            appLog.info("read protected file (Full Disk Access granted?)")
        } catch {
            appLog.error("cannot open \(path, privacy: .public): \(error.localizedDescription, privacy: .public)")
            showError("Permission denied", "Could not open \(path). \(error.localizedDescription)")
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
