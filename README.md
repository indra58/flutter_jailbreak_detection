# flutter_jailbreak_detection

Flutter jailbreak and root detection plugin with **Frida instrumentation detection**.

This plugin wraps Rootbeer for use on Android and IOSSecuritySuite for use on iOS, with additional native Frida detection and hardened root checks.

## Usage

```dart
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';

// Check if device is jailbroken/rooted (original API)
bool jailbroken = await FlutterJailbreakDetection.jailbroken;

// Check if developer mode is enabled / running in emulator
bool devMode = await FlutterJailbreakDetection.developerMode;

// Check if Frida instrumentation framework is detected
bool frida = await FlutterJailbreakDetection.fridaDetected;

// Aggregated check: root + Frida + debugger (recommended for banking apps)
bool compromised = await FlutterJailbreakDetection.isCompromised;
```

## Detection Methods

### `jailbroken` (existing)
- **Android**: Uses RootBeer library
- **iOS**: Uses IOSSecuritySuite

### `developerMode` (existing)
- **Android**: Checks developer settings
- **iOS**: Checks if running in emulator

### `fridaDetected` (new)
- **Android**: Port scanning (27042/27043), `/proc/self/maps` analysis, thread name detection, named pipe detection, debugger check
- **iOS**: Port scanning, dylib analysis, filesystem artifacts, sysctl debugger check

### `isCompromised` (new)
- Aggregated check combining `jailbroken` + `fridaDetected` + native root detection + debugger detection
- Returns `true` if **any** signal is positive
- Recommended for maximum security in banking/financial apps
