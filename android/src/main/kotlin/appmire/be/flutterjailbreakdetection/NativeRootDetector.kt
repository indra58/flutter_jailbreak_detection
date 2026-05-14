package appmire.be.flutterjailbreakdetection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.io.InputStreamReader

/**
 * Native root detection independent of RootBeer.
 *
 * Provides a secondary layer of root detection that uses different techniques
 * than RootBeer, making it harder for a single Frida script to bypass both.
 *
 * Checks:
 * 1. SU binary existence in common paths (obfuscated path construction)
 * 2. Build.TAGS for test-keys (via reflection to resist field hooking)
 * 3. Root management packages (obfuscated package names)
 * 4. Magisk-specific filesystem artifacts
 * 5. /proc/self/mountinfo for suspicious bind mounts
 * 6. SELinux enforcement status
 */
object NativeRootDetector {

    // Build sensitive strings at runtime to resist string scanning
    private fun buildStr(vararg chars: Char): String = String(chars)

    private val SU_STR get() = buildStr('s', 'u')
    private val MAGISK_STR get() = buildStr('m', 'a', 'g', 'i', 's', 'k')
    private val TEST_KEYS get() = buildStr('t', 'e', 's', 't', '-', 'k', 'e', 'y', 's')
    private val WHICH_CMD get() = buildStr('w', 'h', 'i', 'c', 'h')

    /**
     * Master root detection — returns true if ANY root signal is found.
     */
    fun isDeviceRooted(context: Context): Boolean {
        return checkSuBinaryExists() ||
                checkRootBuildTags() ||
                checkRootPackages(context) ||
                checkMagiskPresence() ||
                checkMountInfo() ||
                checkSELinuxPermissive()
    }

    /**
     * Check for su binary in common paths using runtime-built paths.
     */
    private fun checkSuBinaryExists(): Boolean {
        val pathSegments = listOf(
            arrayOf("/system/xbin/", SU_STR),
            arrayOf("/system/bin/", SU_STR),
            arrayOf("/sbin/", SU_STR),
            arrayOf("/data/local/bin/", SU_STR),
            arrayOf("/data/local/xbin/", SU_STR),
            arrayOf("/system/bin/failsafe/", SU_STR),
            arrayOf("/data/local/", SU_STR),
            arrayOf("/system/sd/xbin/", SU_STR),
            arrayOf("/sbin/", MAGISK_STR),
            arrayOf("/data/adb/", MAGISK_STR),
        )

        for (segments in pathSegments) {
            val path = segments.joinToString("")
            try {
                if (File(path).exists()) return true
            } catch (_: Exception) {
                // Continue
            }
        }

        // Also check via "which" command
        try {
            val process = Runtime.getRuntime().exec(arrayOf(WHICH_CMD, SU_STR))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val result = reader.readLine()
            reader.close()
            if (!result.isNullOrBlank()) return true
        } catch (_: Exception) {
            // which not found or su not found
        }

        return false
    }

    /**
     * Check Build.TAGS for "test-keys" using both direct access and reflection.
     * Reflection bypasses Frida's Build field value spoofing.
     */
    private fun checkRootBuildTags(): Boolean {
        try {
            val tags = Build.TAGS
            if (tags != null && tags.contains(TEST_KEYS)) return true

            // Reflection-based check to bypass field value hooking
            val buildClass = Class.forName("android.os.Build")
            val tagsField = buildClass.getField("TAGS")
            val reflectedTags = tagsField.get(null) as? String
            if (reflectedTags != null && reflectedTags.contains(TEST_KEYS)) return true
        } catch (_: Exception) {
            // Ignore
        }
        return false
    }

    /**
     * Check for root management packages using runtime-constructed names.
     */
    private fun checkRootPackages(context: Context): Boolean {
        val packages = listOf(
            "com.topjohnwu.${MAGISK_STR}",
            "com.kingroot.kinguser",
            "com.noshufou.android.${SU_STR}",
            "eu.chainfire.super${SU_STR}",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.${SU_STR}",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.amphoras.hidemyroot",
            "com.formyhm.hiderootPremium",
        )

        val pm = context.packageManager
        for (pkg in packages) {
            try {
                pm.getPackageInfo(pkg, PackageManager.GET_ACTIVITIES)
                return true
            } catch (_: PackageManager.NameNotFoundException) {
                // Not installed
            } catch (_: Exception) {
                // Unexpected
            }
        }
        return false
    }

    /**
     * Check for Magisk-specific filesystem artifacts.
     */
    private fun checkMagiskPresence(): Boolean {
        val magiskPaths = listOf(
            "/sbin/.${MAGISK_STR}",
            "/data/adb/${MAGISK_STR}.img",
            "/data/adb/${MAGISK_STR}",
            "/data/adb/${MAGISK_STR}.db",
            "/cache/${MAGISK_STR}.log",
            "/data/adb/${MAGISK_STR}_simple",
            "/init.${MAGISK_STR}.rc",
        )

        for (path in magiskPaths) {
            try {
                if (File(path).exists()) return true
            } catch (_: Exception) {
                // Continue
            }
        }
        return false
    }

    /**
     * Check /proc/self/mountinfo for Magisk bind mounts.
     */
    private fun checkMountInfo(): Boolean {
        try {
            val mountInfo = File("/proc/self/mountinfo")
            if (!mountInfo.exists()) return false

            BufferedReader(FileReader(mountInfo)).useLines { lines ->
                for (line in lines) {
                    val lower = line.lowercase()
                    if (lower.contains(MAGISK_STR) ||
                        lower.contains("core/mirror") ||
                        lower.contains("core/img")
                    ) {
                        return true
                    }
                }
            }
        } catch (_: Exception) {
            // Ignore
        }
        return false
    }

    /**
     * Check if SELinux is in permissive mode (common on rooted devices).
     */
    private fun checkSELinuxPermissive(): Boolean {
        try {
            val process = Runtime.getRuntime().exec("getenforce")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val result = reader.readLine()?.trim()?.lowercase()
            reader.close()
            process.destroy()
            if (result == "permissive" || result == "disabled") return true
        } catch (_: Exception) {
            // getenforce not available
        }

        try {
            val enforceFile = File("/sys/fs/selinux/enforce")
            if (enforceFile.exists()) {
                val value = BufferedReader(FileReader(enforceFile)).readLine()?.trim()
                if (value == "0") return true
            }
        } catch (_: Exception) {
            // Ignore
        }
        return false
    }
}
