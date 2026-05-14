import 'dart:async';

import 'package:flutter/services.dart';

class FlutterJailbreakDetection {
  static const MethodChannel _channel =
      const MethodChannel('flutter_jailbreak_detection');

  /// Returns `true` if the device is jailbroken (iOS) or rooted (Android).
  /// Uses RootBeer on Android and IOSSecuritySuite on iOS.
  static Future<bool> get jailbroken async {
    bool? jailbroken = await _channel.invokeMethod<bool>('jailbroken');
    return jailbroken ?? true;
  }

  /// Returns `true` if developer mode is enabled (Android)
  /// or if running in an emulator (iOS).
  static Future<bool> get developerMode async {
    bool? developerMode = await _channel.invokeMethod<bool>('developerMode');
    return developerMode ?? true;
  }

  /// Returns `true` if Frida instrumentation framework is detected.
  ///
  /// On Android, checks for:
  /// - Frida server listening ports (27042, 27043)
  /// - Frida libraries in /proc/self/maps (frida-agent, frida-gadget)
  /// - Frida-specific thread names (gmain, gdbus, gum-js-loop)
  /// - Frida named pipes and injectors in /proc/self/fd
  /// - Debugger attachment (TracerPid, Debug.isDebuggerConnected)
  ///
  /// On iOS, checks for:
  /// - Frida listening ports
  /// - Frida dylibs (FridaGadget, frida-agent)
  /// - Frida filesystem artifacts
  /// - Debugger attachment via sysctl (P_TRACED)
  static Future<bool> get fridaDetected async {
    bool? detected = await _channel.invokeMethod<bool>('fridaDetected');
    return detected ?? true;
  }

  /// Returns `true` if ANY compromise signal is detected.
  ///
  /// This is an aggregated check that combines:
  /// - Jailbreak/root detection (RootBeer + native checks)
  /// - Frida instrumentation detection
  /// - Debugger detection
  ///
  /// Use this for maximum security — if any single check returns
  /// positive, the device is considered compromised.
  static Future<bool> get isCompromised async {
    bool? compromised = await _channel.invokeMethod<bool>('isCompromised');
    return compromised ?? true;
  }
}
