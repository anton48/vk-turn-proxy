import SwiftUI
import NetworkExtension

struct ContentView: View {
    @StateObject private var tunnel = TunnelManager()

    // All config stored in AppStorage, edited on SettingsView
    @AppStorage("privateKey") private var privateKey = ""
    @AppStorage("peerPublicKey") private var peerPublicKey = ""
    @AppStorage("presharedKey") private var presharedKey = ""
    @AppStorage("tunnelAddress") private var tunnelAddress = "192.168.102.3/24"
    @AppStorage("dnsServers") private var dnsServers = "1.1.1.1"
    @AppStorage("allowedIPs") private var allowedIPs = "0.0.0.0/0"
    @AppStorage("vkLink") private var vkLink = ""
    @AppStorage("peerAddress") private var peerAddress = ""
    @AppStorage("useDTLS") private var useDTLS = true
    @AppStorage("numConnections") private var numConnections = 16

    var body: some View {
        NavigationView {
            VStack(spacing: 32) {
                Spacer()

                // Status indicator
                Circle()
                    .fill(statusColor)
                    .frame(width: 80, height: 80)
                    .shadow(color: statusColor.opacity(0.5), radius: 12)

                Text(statusText)
                    .font(.title2)
                    .fontWeight(.medium)

                if let error = tunnel.errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                // Stats (shown when connected)
                if tunnel.status == .connected {
                    StatsView(tunnel: tunnel)
                        .padding(.horizontal)
                }

                Spacer()

                // Connect / Disconnect button
                Button(action: {
                    if tunnel.status == .connected || tunnel.status == .connecting {
                        tunnel.disconnect()
                    } else {
                        let config = TunnelConfig(
                            privateKey: privateKey,
                            peerPublicKey: peerPublicKey,
                            presharedKey: presharedKey.isEmpty ? nil : presharedKey,
                            tunnelAddress: tunnelAddress,
                            dnsServers: dnsServers,
                            allowedIPs: allowedIPs,
                            vkLink: vkLink,
                            peerAddress: peerAddress,
                            useDTLS: useDTLS,
                            numConnections: numConnections
                        )
                        Task {
                            await tunnel.connect(config: config)
                        }
                    }
                }) {
                    Text(buttonText)
                        .font(.headline)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(buttonColor)
                        .cornerRadius(12)
                }
                .padding(.horizontal)

                // Settings link
                NavigationLink(destination: SettingsView()) {
                    Label("Settings", systemImage: "gear")
                }
                .padding(.bottom, 24)
            }
            .navigationTitle("VK Turn Proxy")
        }
    }

    // MARK: - Helpers

    private var statusColor: Color {
        switch tunnel.status {
        case .connected: return .green
        case .connecting, .reasserting: return .yellow
        case .disconnecting: return .orange
        default: return .gray
        }
    }

    private var statusText: String {
        switch tunnel.status {
        case .connected: return "Connected"
        case .connecting: return "Connecting..."
        case .disconnecting: return "Disconnecting..."
        case .reasserting: return "Reconnecting..."
        case .disconnected: return "Disconnected"
        case .invalid: return "Invalid"
        @unknown default: return "Unknown"
        }
    }

    private var buttonText: String {
        switch tunnel.status {
        case .connected, .connecting: return "Disconnect"
        default: return "Connect"
        }
    }

    private var buttonColor: Color {
        switch tunnel.status {
        case .connected, .connecting: return .red
        default: return .blue
        }
    }
}

// MARK: - Settings Screen

struct SettingsView: View {
    @AppStorage("privateKey") private var privateKey = ""
    @AppStorage("peerPublicKey") private var peerPublicKey = ""
    @AppStorage("presharedKey") private var presharedKey = ""
    @AppStorage("tunnelAddress") private var tunnelAddress = "192.168.102.3/24"
    @AppStorage("dnsServers") private var dnsServers = "1.1.1.1"
    @AppStorage("allowedIPs") private var allowedIPs = "0.0.0.0/0"
    @AppStorage("vkLink") private var vkLink = ""
    @AppStorage("peerAddress") private var peerAddress = ""
    @AppStorage("useDTLS") private var useDTLS = true
    @AppStorage("numConnections") private var numConnections = 16

    var body: some View {
        Form {
            Section("VK TURN Proxy") {
                TextField("VK Call Link", text: $vkLink)
                    .textContentType(.URL)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                TextField("Proxy Server (host:port)", text: $peerAddress)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                Toggle("DTLS Obfuscation", isOn: $useDTLS)

                Stepper("Connections: \(numConnections)", value: $numConnections, in: 1...64)
            }

            Section("WireGuard") {
                SecureField("Private Key (base64)", text: $privateKey)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                TextField("Peer Public Key (base64)", text: $peerPublicKey)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                SecureField("Preshared Key (base64)", text: $presharedKey)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                TextField("Tunnel Address", text: $tunnelAddress)
                    .autocapitalization(.none)

                TextField("DNS Servers", text: $dnsServers)
                    .autocapitalization(.none)

                TextField("Allowed IPs", text: $allowedIPs)
                    .autocapitalization(.none)
            }
        }
        .navigationTitle("Settings")
    }
}

// MARK: - Stats View

struct StatsView: View {
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        VStack(spacing: 8) {
            HStack {
                StatBox(title: "↑ TX", value: formatBytes(tunnel.stats.txBytes), sub: formatRate(tunnel.txRate))
                StatBox(title: "↓ RX", value: formatBytes(tunnel.stats.rxBytes), sub: formatRate(tunnel.rxRate))
            }

            HStack {
                StatBox(title: "TURN RTT", value: String(format: "%.0f ms", tunnel.stats.turnRTTms), sub: nil)
                StatBox(title: "DTLS HS", value: String(format: "%.0f ms", tunnel.stats.dtlsHandshakeMs), sub: nil)
                StatBox(title: "Internet", value: tunnel.internetRTTms > 0 ? String(format: "%.0f ms", tunnel.internetRTTms) : "—", sub: nil)
            }

            HStack {
                StatBox(title: "Conns", value: "\(tunnel.stats.activeConns)/\(tunnel.stats.totalConns)", sub: nil)
                StatBox(title: "Reconnects", value: "\(tunnel.stats.reconnects)", sub: nil)
            }
        }
    }

    private func formatBytes(_ bytes: Int64) -> String {
        let b = Double(bytes)
        if b >= 1_073_741_824 { return String(format: "%.1f GB", b / 1_073_741_824) }
        if b >= 1_048_576 { return String(format: "%.1f MB", b / 1_048_576) }
        if b >= 1024 { return String(format: "%.1f KB", b / 1024) }
        return "\(bytes) B"
    }

    private func formatRate(_ bytesPerSec: Double) -> String {
        if bytesPerSec >= 1_048_576 { return String(format: "%.1f MB/s", bytesPerSec / 1_048_576) }
        if bytesPerSec >= 1024 { return String(format: "%.1f KB/s", bytesPerSec / 1024) }
        if bytesPerSec > 0 { return String(format: "%.0f B/s", bytesPerSec) }
        return "0 B/s"
    }
}

struct StatBox: View {
    let title: String
    let value: String
    let sub: String?

    var body: some View {
        VStack(spacing: 2) {
            Text(title)
                .font(.caption2)
                .foregroundColor(.secondary)
            Text(value)
                .font(.system(.body, design: .monospaced))
                .fontWeight(.medium)
            if let sub = sub {
                Text(sub)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .background(Color(.systemGray6))
        .cornerRadius(8)
    }
}

#Preview {
    ContentView()
}
