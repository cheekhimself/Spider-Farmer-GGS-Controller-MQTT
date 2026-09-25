package dev.verdant.ggsmonitor

/**
 * Reassemble COMPLETE AA AA 00 03 frames from a stream of FF01 notifies.
 *
 * Rules:
 * - Concatenate ATT fragments that do **not** start with magic onto a truncated
 *   candidate until `declared + 8` bytes are present.
 * - A notify that itself starts with `AA AA 00 03` starts a new candidate
 *   (Matthew's 20-byte headers are independent truncated frames, not bodies).
 * - COMPLETE is emitted only when FrameCodec length matches **and**
 *   CRC-16/MODBUS BE over `frame[:-2]` matches the trailer.
 * - Length-complete CRC failures are `crc_mismatch` (not COMPLETE).
 * - Never decrypts, never invents missing body bytes.
 */
data class AssembledFrame(
    val classification: String,
    val bytes: ByteArray,
    val declaredLength: Int?,
    val crcOk: Boolean,
) {
    val observedLength: Int get() = bytes.size
}

class FrameAssembler {
    private var pending: ByteArray = ByteArray(0)

    fun pendingBytes(): Int = pending.size

    fun reset() {
        pending = ByteArray(0)
    }

    fun push(notify: ByteArray): List<AssembledFrame> {
        if (notify.isEmpty()) return emptyList()
        if (pending.isNotEmpty() && FrameCodec.looksFramed(notify)) {
            // New framed notify: previous truncated candidate had no body.
            pending = ByteArray(0)
        }
        pending = concat(pending, notify)
        val emitted = ArrayList<AssembledFrame>()
        while (true) {
            val parsed = FrameCodec.parse(pending)
            when {
                parsed.ok && parsed.length != null -> {
                    val total = parsed.length + FrameCodec.LENGTH_ENVELOPE
                    val frame = pending.copyOfRange(0, total)
                    val crcOk = Crc16.trailerMatches(frame)
                    emitted.add(
                        AssembledFrame(
                            classification = if (crcOk) {
                                FrameCodec.CLASS_COMPLETE
                            } else {
                                FrameCodec.CLASS_CRC_MISMATCH
                            },
                            bytes = frame,
                            declaredLength = parsed.length,
                            crcOk = crcOk,
                        ),
                    )
                    pending = parsed.leftover
                }
                parsed.error == FrameCodec.ERROR_TRUNCATED ||
                    parsed.error == FrameCodec.ERROR_TOO_SHORT -> {
                    break
                }
                else -> {
                    val nextMagic = indexOfMagic(pending, fromIndex = 1)
                    if (nextMagic < 0) {
                        pending = keepPartialMagic(pending)
                        break
                    }
                    pending = pending.copyOfRange(nextMagic, pending.size)
                }
            }
        }
        return emitted
    }

    companion object {
        private fun concat(left: ByteArray, right: ByteArray): ByteArray {
            if (left.isEmpty()) return right.copyOf()
            return left + right
        }

        private fun indexOfMagic(data: ByteArray, fromIndex: Int): Int {
            val magic = FrameCodec.MAGIC
            if (data.size - fromIndex < magic.size) return -1
            for (i in fromIndex..(data.size - magic.size)) {
                var match = true
                for (j in magic.indices) {
                    if (data[i + j] != magic[j]) {
                        match = false
                        break
                    }
                }
                if (match) return i
            }
            return -1
        }

        private fun keepPartialMagic(data: ByteArray): ByteArray {
            val keep = minOf(FrameCodec.MAGIC.size - 1, data.size)
            return if (keep <= 0) ByteArray(0) else data.copyOfRange(data.size - keep, data.size)
        }
    }
}
