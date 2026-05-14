## 1.13.0

* **Frida instrumentation detection** — new `fridaDetected` API
  - Android: Port scanning, /proc/self/maps, thread names, named pipes, debugger check
  - iOS: Port scanning, dylib analysis, filesystem artifacts, sysctl debugger check
* **Aggregated compromise check** — new `isCompromised` API
  - Combines root/jailbreak + Frida + native root detection + debugger detection
  - Returns true if ANY signal is positive
* **Native root detection** (Android) — independent of RootBeer
  - Obfuscated string construction to resist Frida string scanning
  - Reflection-based Build.TAGS check to bypass field hooking
  - Magisk mount namespace detection
  - SELinux enforcement check
* Fully backward compatible with existing `jailbroken` and `developerMode` APIs

## 1.8.0

* Upgrade android embedding
  Thanks https://github.com/xPutnikx for the PR.
  
* Fixed header issue
  Thanks https://github.com/cr0manty for the PR.

## 1.7.0

* Upgrade rootbeer to 0.0.10
Thanks https://github.com/patuoynageek for the PR.

## 1.6.0

* Upgrade rootbeer to 0.0.9

## 1.5.0
Upgrade to kotlin 1.3.30. Thanks https://github.com/kmoorejr9 for the PR.
Support for null safety.  Thanks https://github.com/tvh for the PR.
Rootbeer dependency fix. Thanks https://github.com/benoitskipr for the PR.

## 1.4.0

* Change some formatting, move package to appmire publisher.

## 1.3.0

* Update rootbeer dependency url. Thanks https://github.com/sckoh for the PR.

## 1.2.0

* Upgrade rootbeer plugin. Thanks https://github.com/zaralockheart for the PR.

## 1.1.0

* Prevent plugin initialization when Activity is not available

## 1.0.0

* Upgrade gradle plugin and support for AndroidX

