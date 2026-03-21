import NetworkExtension
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var tunnelHandle: Int32 = -1
    private let log = OSLog(subsystem: "com.vkturnproxy.tunnel", category: "PacketTunnel")

    private func logMsg(_ msg: String) {
        os_log("%{public}s", log: log, type: .default, msg)
        NSLog("[PacketTunnel] %@", msg)
    }

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {

        logMsg("startTunnel called")

        guard let config = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration else {
            logMsg("ERROR: no provider configuration")
            completionHandler(VPNError.noConfiguration)
            return
        }

        guard let wgConfig = config["wg_config"] as? String,
              let proxyConfigJSON = config["proxy_config"] as? String else {
            logMsg("ERROR: missing wg_config or proxy_config")
            completionHandler(VPNError.invalidConfiguration)
            return
        }

        let tunnelAddress = config["tunnel_address"] as? String ?? "192.168.102.3/24"
        let dnsServers = config["dns_servers"] as? String ?? "1.1.1.1"
        let mtu = config["mtu"] as? String ?? "1280"

        logMsg("tunnelAddress=\(tunnelAddress) dns=\(dnsServers) mtu=\(mtu)")
        logMsg("proxyConfig=\(proxyConfigJSON)")

        // Parse proxy config to extract peer address for route exclusion
        var peerHost: String?
        if let proxyData = proxyConfigJSON.data(using: .utf8),
           let proxyDict = try? JSONSerialization.jsonObject(with: proxyData) as? [String: Any],
           let peerAddr = proxyDict["peer_addr"] as? String {
            let host = peerAddr.split(separator: ":").first.map(String.init)
            peerHost = host
            logMsg("peerHost=\(host ?? "nil")")
        } else {
            logMsg("WARNING: could not parse peer_addr from proxy config")
        }

        // PHASE 1: Set initial network settings WITHOUT capturing all traffic.
        // This creates the TUN interface so we can get its file descriptor.
        let initialSettings = createTunnelSettings(
            address: tunnelAddress,
            dns: dnsServers,
            mtu: mtu,
            captureTraffic: false,
            excludeHosts: []
        )

        logMsg("PHASE 1: setting initial tunnel settings (no routes)")
        setTunnelNetworkSettings(initialSettings) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.logMsg("PHASE 1 ERROR: \(error)")
                completionHandler(error)
                return
            }
            self.logMsg("PHASE 1: settings applied OK")

            guard let tunFd = self.findTunFileDescriptor() else {
                self.logMsg("ERROR: could not find TUN fd")
                completionHandler(VPNError.noTunDevice)
                return
            }
            self.logMsg("TUN fd=\(tunFd)")

            // Start WireGuard + TURN proxy
            self.logMsg("calling wgTurnOnWithTURN...")
            let handle = wgConfig.withCString { settingsPtr in
                proxyConfigJSON.withCString { proxyPtr in
                    wgTurnOnWithTURN(
                        UnsafeMutablePointer(mutating: settingsPtr),
                        tunFd,
                        UnsafeMutablePointer(mutating: proxyPtr)
                    )
                }
            }

            if handle < 0 {
                self.logMsg("ERROR: wgTurnOnWithTURN returned \(handle)")
                completionHandler(VPNError.backendFailed(code: handle))
                return
            }

            self.tunnelHandle = handle
            self.logMsg("wgTurnOnWithTURN OK, handle=\(handle)")

            // PHASE 2: Set final settings with default route and excluded routes
            // for TURN server and peer server IPs (so their traffic bypasses the tunnel).
            var excludeHosts: [String] = []
            if let peer = peerHost {
                excludeHosts.append(peer)
            }

            if let turnIPPtr = wgGetTURNServerIP(handle) {
                let turnIP = String(cString: turnIPPtr)
                free(UnsafeMutableRawPointer(mutating: turnIPPtr))
                if !turnIP.isEmpty {
                    excludeHosts.append(turnIP)
                    self.logMsg("TURN server IP=\(turnIP)")
                } else {
                    self.logMsg("WARNING: TURN server IP is empty")
                }
            } else {
                self.logMsg("WARNING: wgGetTURNServerIP returned nil")
            }

            self.logMsg("PHASE 2: excludeHosts=\(excludeHosts)")

            let finalSettings = self.createTunnelSettings(
                address: tunnelAddress,
                dns: dnsServers,
                mtu: mtu,
                captureTraffic: true,
                excludeHosts: excludeHosts
            )

            self.logMsg("PHASE 2: applying final settings with default route")
            self.setTunnelNetworkSettings(finalSettings) { error in
                if let error = error {
                    self.logMsg("PHASE 2 ERROR: \(error)")
                    completionHandler(error)
                    return
                }
                self.logMsg("PHASE 2: settings applied OK - tunnel ready")
                completionHandler(nil)
            }
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let msg = String(data: messageData, encoding: .utf8) else {
            completionHandler?(nil)
            return
        }

        if msg == "get_stats" {
            guard tunnelHandle >= 0 else {
                completionHandler?(nil)
                return
            }
            if let ptr = wgGetStats(tunnelHandle) {
                let json = String(cString: ptr)
                free(UnsafeMutableRawPointer(mutating: ptr))
                completionHandler?(json.data(using: .utf8))
            } else {
                completionHandler?(nil)
            }
        } else {
            completionHandler?(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        if tunnelHandle >= 0 {
            wgTurnOff(tunnelHandle)
            tunnelHandle = -1
        }
        completionHandler()
    }

    // MARK: - Network Settings

    private func createTunnelSettings(
        address: String,
        dns: String,
        mtu: String,
        captureTraffic: Bool,
        excludeHosts: [String]
    ) -> NEPacketTunnelNetworkSettings {
        let parts = address.split(separator: "/")
        let ip = String(parts[0])
        let prefix = parts.count > 1 ? Int(parts[1]) ?? 24 : 24

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.1")

        let ipv4 = NEIPv4Settings(addresses: [ip], subnetMasks: [prefixToSubnet(prefix)])

        if captureTraffic {
            ipv4.includedRoutes = [NEIPv4Route.default()]
            ipv4.excludedRoutes = excludeHosts.map {
                NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255")
            }
        }

        settings.ipv4Settings = ipv4

        // Only set DNS in Phase 2 (captureTraffic=true).
        // Setting DNS in Phase 1 can cause Go HTTP requests to hang
        // because the TUN interface isn't routing traffic yet.
        if captureTraffic {
            let dnsAddresses = dns.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) }
            settings.dnsSettings = NEDNSSettings(servers: dnsAddresses)
        }

        if let mtuInt = Int(mtu) {
            settings.mtu = NSNumber(value: mtuInt)
        }

        return settings
    }

    private func prefixToSubnet(_ prefix: Int) -> String {
        var mask: UInt32 = 0
        for i in 0..<prefix {
            mask |= (1 << (31 - i))
        }
        return "\(mask >> 24).\((mask >> 16) & 0xFF).\((mask >> 8) & 0xFF).\(mask & 0xFF)"
    }

    // MARK: - TUN File Descriptor Discovery

    private func findTunFileDescriptor() -> Int32? {
        var buf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        for fd: Int32 in 0...1024 {
            var len = socklen_t(buf.count)
            if getsockopt(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */, &buf, &len) == 0 {
                let name = String(cString: buf)
                if name.hasPrefix("utun") {
                    return fd
                }
            }
        }
        return nil
    }
}

// MARK: - Errors

enum VPNError: Error, LocalizedError {
    case noConfiguration
    case invalidConfiguration
    case noTunDevice
    case backendFailed(code: Int32)

    var errorDescription: String? {
        switch self {
        case .noConfiguration: return "No provider configuration found"
        case .invalidConfiguration: return "Invalid or missing configuration fields"
        case .noTunDevice: return "Could not find TUN file descriptor"
        case .backendFailed(let code): return "WireGuard backend failed with code \(code)"
        }
    }
}
