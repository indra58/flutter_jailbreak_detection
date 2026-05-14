import Flutter
import UIKit
import IOSSecuritySuite
public class SwiftFlutterJailbreakDetectionPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "flutter_jailbreak_detection", binaryMessenger: registrar.messenger())
    let instance = SwiftFlutterJailbreakDetectionPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "jailbroken":
            
            let check2 = IOSSecuritySuite.amIJailbroken()
            result(check2)
            break
        case "developerMode":
            result(IOSSecuritySuite.amIRunInEmulator())
            break
        case "fridaDetected":
            let fridaDetected = isFridaDetected()
            result(fridaDetected)
            break
        case "isCompromised":
            let jailbroken = IOSSecuritySuite.amIJailbroken()
            let fridaDetected = isFridaDetected()
            let debuggerAttached = IOSSecuritySuite.amIDebugged()
            result(jailbroken || fridaDetected || debuggerAttached)
            break
        default:
            result(FlutterMethodNotImplemented)
        }
  }

  /// Detects Frida instrumentation on iOS via multiple signals.
  private func isFridaDetected() -> Bool {
      return checkFridaPorts() ||
             checkFridaLibraries() ||
             checkFridaNamedPipes() ||
             isDebuggerAttached()
  }

  /// Check if Frida's default port (27042) is listening.
  private func checkFridaPorts() -> Bool {
      let ports: [Int32] = [27042, 27043]
      for port in ports {
          let sock = socket(AF_INET, SOCK_STREAM, 0)
          guard sock >= 0 else { continue }

          var addr = sockaddr_in()
          addr.sin_family = sa_family_t(AF_INET)
          addr.sin_port = in_port_t(port).bigEndian
          addr.sin_addr.s_addr = inet_addr("127.0.0.1")

          let addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
          let connected = withUnsafePointer(to: &addr) {
              $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                  connect(sock, $0, addrLen)
              }
          }
          close(sock)
          if connected == 0 { return true }
      }
      return false
  }

  /// Check loaded dylibs for Frida-related libraries.
  private func checkFridaLibraries() -> Bool {
      let fridaSigs = ["FridaGadget", "frida-agent", "libfrida"]
      let imageCount = _dyld_image_count()
      for i in 0..<imageCount {
          if let imageName = _dyld_get_image_name(i) {
              let name = String(cString: imageName).lowercased()
              for sig in fridaSigs {
                  if name.contains(sig.lowercased()) { return true }
              }
          }
      }
      return false
  }

  /// Check for Frida-related named pipes or listener files.
  private func checkFridaNamedPipes() -> Bool {
      let suspiciousPaths = [
          "/usr/lib/frida",
          "/usr/local/lib/frida",
      ]
      for path in suspiciousPaths {
          if FileManager.default.fileExists(atPath: path) { return true }
      }
      return false
  }

  /// Check if a debugger (e.g. Frida/LLDB) is attached via sysctl.
  private func isDebuggerAttached() -> Bool {
      var info = kinfo_proc()
      var size = MemoryLayout<kinfo_proc>.stride
      var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
      let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
      if result == 0 {
          return (info.kp_proc.p_flag & P_TRACED) != 0
      }
      return false
  }
}
