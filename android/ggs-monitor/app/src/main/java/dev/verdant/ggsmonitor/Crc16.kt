package dev.verdant.ggsmonitor

/**
 * CRC-16/MODBUS used by Phase 4 live COMPLETE dumps.
 *
 * poly 0x8005 reflected (0xA001), init 0xFFFF, xorout 0, refin/refout.
 * Trailer rule (proven 45/45 on live_phase3): big-endian CRC over frame[:-2]
 * equals the last two bytes. This is not decrypt.
 */
object Crc16 {
    const val TRAILER_SIZE: Int = 2

    fun modbus(data: ByteArray): Int {
        var crc = 0xFFFF
        for (byte in data) {
            crc = crc xor (byte.toInt() and 0xFF)
            repeat(8) {
                crc = if ((crc and 1) != 0) {
                    (crc ushr 1) xor 0xA001
                } else {
                    crc ushr 1
                }
            }
        }
        return crc and 0xFFFF
    }

    fun modbusBe(data: ByteArray): ByteArray {
        val crc = modbus(data)
        return byteArrayOf(((crc shr 8) and 0xFF).toByte(), (crc and 0xFF).toByte())
    }

    /**
     * Fail-closed trailer check. Short buffers and mismatches return false.
     */
    fun trailerMatches(frame: ByteArray): Boolean {
        if (frame.size < TRAILER_SIZE) return false
        val covered = frame.copyOfRange(0, frame.size - TRAILER_SIZE)
        val expected = modbusBe(covered)
        val actual = frame.copyOfRange(frame.size - TRAILER_SIZE, frame.size)
        return expected.contentEquals(actual)
    }
}
