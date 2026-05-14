package appmire.be.flutterjailbreakdetection

import android.os.Debug
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Detects the presence of Frida instrumentation framework.
 *
 * Checks multiple signals:
 * 1. Frida default listening ports (27042, 27043)
 * 2. Frida libraries in /proc/self/maps
 * 3. Frida-specific thread names in /proc/self/task
 * 4. Frida named pipes / injectors in /proc/self/fd
 * 5. Debugger attachment (TracerPid + Debug API)
 *
 * Uses obfuscated string construction to resist Frida's own
 * string-scanning bypass techniques.
 */
object FridaDetector {

    // Build critical strings at runtime from char arrays
    // to prevent Frida from finding them via simple string search.
    private fun buildStr(vararg chars: Char): String = String(chars)

    private val FRIDA_STR get() = buildStr('f', 'r', 'i', 'd', 'a')

    /**
     * Master Frida detection — returns true if ANY signal is found.
     */
    fun isFridaDetected(): Boolean {
        return checkFridaPorts() ||
                checkFridaInMaps() ||
                checkFridaThreads() ||
                checkFridaNamedPipes() ||
                isDebuggerAttached()
    }

    /**
     * Check if Frida's default listening ports are open.
     * Frida server listens on 27042 (default) and 27043.
     */
    private fun checkFridaPorts(): Boolean {
        val ports = intArrayOf(27042, 27043)
        for (port in ports) {
            try {
                val socket = Socket()
                socket.connect(InetSocketAddress("127.0.0.1", port), 200)
                socket.close()
                return true
            } catch (_: Exception) {
                // Port not open — continue
            }
        }
        return false
    }

    /**
     * Read /proc/self/maps for Frida-related shared libraries.
     * Frida injects frida-agent.so / frida-gadget.so into the target process.
     */
    private fun checkFridaInMaps(): Boolean {
        try {
            val mapsFile = File("/proc/self/maps")
            if (!mapsFile.exists()) return false

            val fridaSignatures = listOf(
                "${FRIDA_STR}-agent",
                "${FRIDA_STR}-gadget",
                "lib${FRIDA_STR}",
                "${FRIDA_STR}-server"
            )

            BufferedReader(FileReader(mapsFile)).useLines { lines ->
                for (line in lines) {
                    val lower = line.lowercase()
                    for (sig in fridaSignatures) {
                        if (lower.contains(sig)) return true
                    }
                }
            }
        } catch (_: Exception) {
            // Cannot read maps — ignore
        }
        return false
    }

    /**
     * Check thread names for Frida-specific threads.
     * Frida spawns threads named "gmain", "gdbus", "gum-js-loop".
     */
    private fun checkFridaThreads(): Boolean {
        try {
            val taskDir = File("/proc/self/task")
            if (!taskDir.exists() || !taskDir.isDirectory) return false

            val fridaThreadNames = listOf(
                "gmain",
                "gdbus",
                "gum-js-loop",
                "${FRIDA_STR}-helper"
            )

            taskDir.listFiles()?.forEach { threadDir ->
                try {
                    val statusFile = File(threadDir, "status")
                    if (statusFile.exists()) {
                        val reader = BufferedReader(FileReader(statusFile))
                        val firstLine = reader.readLine() ?: ""
                        reader.close()
                        val threadName = firstLine.substringAfter("Name:").trim().lowercase()
                        for (sig in fridaThreadNames) {
                            if (threadName.contains(sig)) return true
                        }
                    }
                } catch (_: Exception) {
                    // Skip unreadable threads
                }
            }
        } catch (_: Exception) {
            // Fail open for this sub-check
        }
        return false
    }

    /**
     * Check for Frida named pipes and injectors in /proc/self/fd.
     */
    private fun checkFridaNamedPipes(): Boolean {
        try {
            val fdDir = File("/proc/self/fd")
            if (!fdDir.exists()) return false

            fdDir.listFiles()?.forEach { fd ->
                try {
                    val link = fd.canonicalPath
                    if (link.contains(FRIDA_STR) || link.contains("linjector")) {
                        return true
                    }
                } catch (_: Exception) {
                    // Skip unresolvable symlinks
                }
            }
        } catch (_: Exception) {
            // Fail open for this sub-check
        }
        return false
    }

    /**
     * Check if a debugger is attached (TracerPid or Android Debug API).
     */
    private fun isDebuggerAttached(): Boolean {
        // Check 1: Android Debug API
        if (Debug.isDebuggerConnected()) return true

        // Check 2: TracerPid in /proc/self/status
        try {
            val statusFile = File("/proc/self/status")
            if (statusFile.exists()) {
                BufferedReader(FileReader(statusFile)).useLines { lines ->
                    for (line in lines) {
                        if (line.startsWith("TracerPid:")) {
                            val pid = line.substringAfter("TracerPid:").trim().toIntOrNull() ?: 0
                            if (pid != 0) return true
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // Ignore
        }
        return false
    }
}
