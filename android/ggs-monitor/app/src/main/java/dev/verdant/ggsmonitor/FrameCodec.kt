package dev.verdant.ggsmonitor

/**
 * Fail-closed AA AA 00 03 frame detector (receive-only; no decrypt).
 *
 * Port of verdant_integration/frame_codec.py. Header layout (Cheek, Windows G7,
 * 2026-09-16; 32/32 FRAMED_CANDIDATE):
 *
 *     offset  size  field
 *     0-3     4     magic / version-ish  AA AA 00 03
 *     4-5     2     declared length, big-endian uint16
 *     6-end         opaque body (not interpreted)
 *
 * total_size = declared_length + 8
 */
data class FrameParseResult(
    val ok: Boolean,
    val error: String?,
    val length: Int?,
    val header: ByteArray,
    val payload: ByteArray,
    val leftover: ByteArray,
) {
    fun classification(): String {
        return if (ok) FrameCodec.CLASS_COMPLETE else (error ?: FrameCodec.CLASS_UNKNOWN)
    }
}

object FrameCodec {
    val MAGIC: ByteArray = byteArrayOf(0xAA.toByte(), 0xAA.toByte(), 0x00, 0x03)
    const val HEADER_SIZE: Int = 6
    const val LENGTH_ENVELOPE: Int = 8
    const val MAX_DECLARED_LENGTH: Int = 2048

    const val ERROR_TOO_SHORT: String = "too_short"
    const val ERROR_PLAINTEXT_JSON: String = "plaintext_json"
    const val ERROR_NOT_FRAMED: String = "not_framed"
    const val ERROR_INVALID_LENGTH: String = "invalid_length"
    const val ERROR_TRUNCATED: String = "truncated"
    const val CLASS_COMPLETE: String = "complete"
    const val CLASS_UNKNOWN: String = "unknown"

    fun looksFramed(data: ByteArray): Boolean {
        if (data.size < MAGIC.size) return false
        return data.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)
    }

    fun looksPlaintextJson(data: ByteArray): Boolean {
        val buffer = stripLeadingWhitespace(data)
        if (buffer.isEmpty()) return false
        val first = buffer[0]
        return first == '{'.code.toByte() || first == '['.code.toByte()
    }

    fun parse(data: ByteArray): FrameParseResult {
        if (looksPlaintextJson(data)) {
            return FrameParseResult(
                ok = false,
                error = ERROR_PLAINTEXT_JSON,
                length = null,
                header = ByteArray(0),
                payload = ByteArray(0),
                leftover = ByteArray(0),
            )
        }
        if (data.size < HEADER_SIZE) {
            return FrameParseResult(
                ok = false,
                error = ERROR_TOO_SHORT,
                length = null,
                header = data.copyOf(),
                payload = ByteArray(0),
                leftover = ByteArray(0),
            )
        }
        if (!looksFramed(data)) {
            return FrameParseResult(
                ok = false,
                error = ERROR_NOT_FRAMED,
                length = null,
                header = ByteArray(0),
                payload = ByteArray(0),
                leftover = ByteArray(0),
            )
        }
        val declared = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        val header = data.copyOfRange(0, HEADER_SIZE)
        if (declared < 1 || declared > MAX_DECLARED_LENGTH) {
            return FrameParseResult(
                ok = false,
                error = ERROR_INVALID_LENGTH,
                length = declared,
                header = header,
                payload = ByteArray(0),
                leftover = ByteArray(0),
            )
        }
        val total = declared + LENGTH_ENVELOPE
        if (data.size < total) {
            return FrameParseResult(
                ok = false,
                error = ERROR_TRUNCATED,
                length = declared,
                header = header,
                payload = ByteArray(0),
                leftover = ByteArray(0),
            )
        }
        return FrameParseResult(
            ok = true,
            error = null,
            length = declared,
            header = header,
            payload = data.copyOfRange(HEADER_SIZE, total),
            leftover = if (data.size > total) data.copyOfRange(total, data.size) else ByteArray(0),
        )
    }

    private fun stripLeadingWhitespace(data: ByteArray): ByteArray {
        var i = 0
        while (i < data.size) {
            val b = data[i].toInt() and 0xFF
            if (b != 0x09 && b != 0x0A && b != 0x0B && b != 0x0C && b != 0x0D && b != 0x20) {
                break
            }
            i += 1
        }
        return if (i == 0) data else data.copyOfRange(i, data.size)
    }
}

fun ByteArray.toHexSpaced(): String {
    if (isEmpty()) return ""
    val out = StringBuilder(size * 3)
    forEachIndexed { index, byte ->
        if (index > 0) out.append(' ')
        out.append("%02X".format(byte.toInt() and 0xFF))
    }
    return out.toString()
}

fun ByteArray.toHexCompact(): String {
    val out = StringBuilder(size * 2)
    forEach { byte -> out.append("%02X".format(byte.toInt() and 0xFF)) }
    return out.toString()
}
