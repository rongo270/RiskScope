package com.rongo.riskscope.scan

import java.io.File
import java.security.MessageDigest

/**
 * Computes the hash of an APK FILE (not the signing certificate). This is the
 * SHA-256 that malware databases such as MalwareBazaar index, so it is what we
 * send to the server for a reputation check.
 */
object ApkHasher {

    private const val BUFFER_SIZE = 64 * 1024

    /** Streaming SHA-256 of a file, lowercase hex, or null if it can't be read. */
    fun sha256(path: String?): String? = digest(path, "SHA-256")

    fun digest(path: String?, algorithm: String): String? {
        if (path.isNullOrBlank()) return null
        val file = File(path)
        if (!file.isFile) return null
        return try {
            val md = MessageDigest.getInstance(algorithm)
            file.inputStream().use { input ->
                val buffer = ByteArray(BUFFER_SIZE)
                while (true) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    md.update(buffer, 0, read)
                }
            }
            md.digest().toHex()
        } catch (e: Exception) {
            null
        }
    }

    fun bytesToHex(bytes: ByteArray): String = bytes.toHex()

    private fun ByteArray.toHex(): String {
        val out = StringBuilder(size * 2)
        for (b in this) {
            val v = b.toInt() and 0xFF
            out.append(HEX[v ushr 4])
            out.append(HEX[v and 0x0F])
        }
        return out.toString()
    }

    private val HEX = "0123456789abcdef".toCharArray()
}
