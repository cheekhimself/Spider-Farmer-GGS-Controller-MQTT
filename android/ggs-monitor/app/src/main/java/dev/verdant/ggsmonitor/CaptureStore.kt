package dev.verdant.ggsmonitor

import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.TimeZone

data class CapturedFrame(
    val sequence: Int,
    val epochMs: Long,
    val bytes: ByteArray,
    val classification: String,
    val declaredLength: Int?,
    val observedLength: Int,
    val leftoverBytes: Int,
) {
    fun isoTimestamp(): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return fmt.format(Date(epochMs))
    }

    fun previewHex(maxBytes: Int = 48): String {
        val shown = if (bytes.size <= maxBytes) bytes else bytes.copyOfRange(0, maxBytes)
        val suffix = if (bytes.size > maxBytes) " …" else ""
        return shown.toHexSpaced() + suffix
    }

    fun line(): String {
        val declared = declaredLength?.toString() ?: "-"
        return "#$sequence ${isoTimestamp()} class=$classification declared=$declared observed=$observedLength leftover=$leftoverBytes hex=${previewHex()}"
    }
}

class CaptureStore(private val maxFrames: Int = MAX_FRAMES) {
    private val frames = ArrayDeque<CapturedFrame>()
    var packetCount: Int = 0
        private set
    var byteCount: Long = 0
        private set
    var lastEpochMs: Long? = null
        private set

    fun add(raw: ByteArray, nowMs: Long): CapturedFrame {
        val parsed = FrameCodec.parse(raw)
        packetCount += 1
        byteCount += raw.size.toLong()
        lastEpochMs = nowMs
        val frame = CapturedFrame(
            sequence = packetCount,
            epochMs = nowMs,
            bytes = raw.copyOf(),
            classification = parsed.classification(),
            declaredLength = parsed.length,
            observedLength = raw.size,
            leftoverBytes = parsed.leftover.size,
        )
        frames.addLast(frame)
        while (frames.size > maxFrames) {
            frames.removeFirst()
        }
        return frame
    }

    fun clear() {
        frames.clear()
        packetCount = 0
        byteCount = 0
        lastEpochMs = null
    }

    fun snapshot(): List<CapturedFrame> = frames.toList()

    fun renderLog(): String {
        if (frames.isEmpty()) return "(no FF01 frames yet)"
        return frames.joinToString("\n") { it.line() }
    }

    fun exportText(meta: Map<String, String>): String {
        val lines = ArrayList<String>()
        lines.add("# GGS Monitor capture — receive-only FF01")
        lines.add("# Live sensor decoding: UNAVAILABLE until vendor key material is proven.")
        lines.add("# This file is hex/classification only. No decrypted values.")
        meta.forEach { (k, v) -> lines.add("# $k: $v") }
        lines.add("# packets=$packetCount bytes=$byteCount frames_retained=${frames.size}")
        snapshot().forEach { frame ->
            lines.add(
                listOf(
                    frame.sequence.toString(),
                    frame.isoTimestamp(),
                    frame.classification,
                    (frame.declaredLength ?: -1).toString(),
                    frame.observedLength.toString(),
                    frame.bytes.toHexCompact(),
                ).joinToString("\t"),
            )
        }
        return lines.joinToString("\n") + "\n"
    }

    companion object {
        const val MAX_FRAMES: Int = 200
    }
}
