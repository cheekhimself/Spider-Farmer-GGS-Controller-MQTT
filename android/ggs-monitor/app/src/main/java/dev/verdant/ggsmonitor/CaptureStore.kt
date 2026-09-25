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
    val crcOk: Boolean? = null,
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
        val crc = when (crcOk) {
            true -> " crc=ok"
            false -> " crc=mismatch"
            null -> ""
        }
        return "#$sequence ${isoTimestamp()} class=$classification declared=$declared observed=$observedLength leftover=$leftoverBytes$crc hex=${previewHex()}"
    }
}

class CaptureStore(private val maxFrames: Int = MAX_FRAMES) {
    private val assembler = FrameAssembler()
    private val frames = ArrayDeque<CapturedFrame>()
    private val completeFrames = ArrayDeque<CapturedFrame>()
    var packetCount: Int = 0
        private set
    var byteCount: Long = 0
        private set
    var completeCount: Int = 0
        private set
    var crcMismatchCount: Int = 0
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
        for (assembled in assembler.push(raw)) {
            if (assembled.crcOk) {
                completeCount += 1
                completeFrames.addLast(
                    CapturedFrame(
                        sequence = completeCount,
                        epochMs = nowMs,
                        bytes = assembled.bytes.copyOf(),
                        classification = assembled.classification,
                        declaredLength = assembled.declaredLength,
                        observedLength = assembled.observedLength,
                        leftoverBytes = 0,
                        crcOk = true,
                    ),
                )
                while (completeFrames.size > maxFrames) {
                    completeFrames.removeFirst()
                }
            } else {
                crcMismatchCount += 1
            }
        }
        return frame
    }

    fun clear() {
        assembler.reset()
        frames.clear()
        completeFrames.clear()
        packetCount = 0
        byteCount = 0
        completeCount = 0
        crcMismatchCount = 0
        lastEpochMs = null
    }

    fun snapshot(): List<CapturedFrame> = frames.toList()

    fun completeSnapshot(): List<CapturedFrame> = completeFrames.toList()

    fun completeSummary(): String {
        if (completeCount == 0) {
            return "complete: 0 (no COMPLETE reassembled)"
        }
        val sizes = completeSnapshot().joinToString(",") { frame ->
            "${frame.observedLength}B/${frame.declaredLength ?: "-"}"
        }
        return "complete: $completeCount sizes=[$sizes] crc_mismatch=$crcMismatchCount"
    }

    fun renderLog(): String {
        val parts = ArrayList<String>()
        parts.add("=== COMPLETE reassembled (${completeCount}) ===")
        if (completeFrames.isEmpty()) {
            parts.add("(none — headers-only / truncated notifies stay in RAW)")
        } else {
            completeFrames.forEach { parts.add(it.line()) }
        }
        parts.add("=== RAW notifies (${frames.size} retained / $packetCount total) ===")
        if (frames.isEmpty()) {
            parts.add("(no FF01 frames yet)")
        } else {
            frames.forEach { parts.add(it.line()) }
        }
        return parts.joinToString("\n")
    }

    fun exportText(meta: Map<String, String>): String {
        val lines = ArrayList<String>()
        lines.add("# GGS Monitor capture — receive-only FF01")
        lines.add("# Live sensor decoding: UNAVAILABLE until vendor key material is proven.")
        lines.add("# This file is hex/classification only. No decrypted values.")
        meta.forEach { (k, v) -> lines.add("# $k: $v") }
        lines.add("# packets=$packetCount bytes=$byteCount frames_retained=${frames.size}")
        lines.add("# complete_reassembled=$completeCount crc_mismatch=$crcMismatchCount")
        if (completeCount == 0) {
            lines.add("# COMPLETE: none (no COMPLETE reassembled)")
        }
        lines.add("# --- COMPLETE reassembled frames ---")
        if (completeFrames.isEmpty()) {
            lines.add("# (none)")
        } else {
            completeSnapshot().forEach { frame ->
                lines.add(exportRow(frame, includeCrc = true))
            }
        }
        lines.add("# --- RAW notifies ---")
        snapshot().forEach { frame ->
            lines.add(exportRow(frame, includeCrc = false))
        }
        return lines.joinToString("\n") + "\n"
    }

    private fun exportRow(frame: CapturedFrame, includeCrc: Boolean): String {
        val cols = mutableListOf(
            frame.sequence.toString(),
            frame.isoTimestamp(),
            frame.classification,
            (frame.declaredLength ?: -1).toString(),
            frame.observedLength.toString(),
            frame.bytes.toHexCompact(),
        )
        if (includeCrc) {
            cols.add(if (frame.crcOk == true) "crc=ok" else "crc=mismatch")
        }
        return cols.joinToString("\t")
    }

    companion object {
        const val MAX_FRAMES: Int = 200
    }
}
