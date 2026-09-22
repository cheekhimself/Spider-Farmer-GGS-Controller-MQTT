package dev.verdant.ggsmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class FrameCodecTest {
    @Test
    fun parsesObservedSizeClasses() {
        val classes = listOf(
            Triple(422, 414, 0x019E),
            Triple(390, 382, 0x017E),
            Triple(246, 238, 0x00EE),
            Triple(230, 222, 0x00DE),
        )
        for ((total, declared, encoded) in classes) {
            val buffer = framedBuffer(declared, total)
            assertEquals(encoded, declared)
            assertEquals(total, buffer.size)
            val result = FrameCodec.parse(buffer)
            assertTrue(result.ok)
            assertNull(result.error)
            assertEquals(declared, result.length)
            assertTrue(buffer.copyOfRange(0, 4).contentEquals(FrameCodec.MAGIC))
            assertEquals(total - 6, result.payload.size)
            assertEquals(0, result.leftover.size)
            assertTrue(FrameCodec.looksFramed(buffer))
            assertEquals(FrameCodec.CLASS_COMPLETE, result.classification())
        }
    }

    @Test
    fun leftoverBytesAfterOneCompleteFrame() {
        val buffer = framedBuffer(222, 230) + byteArrayOf(0x00, 0x01)
        val result = FrameCodec.parse(buffer)
        assertTrue(result.ok)
        assertEquals(222, result.length)
        assertTrue(result.leftover.contentEquals(byteArrayOf(0x00, 0x01)))
    }

    @Test
    fun rejectsPlaintextJson() {
        val plaintext = """{"method":"getDevSta","data":{"sensor":{"temp":1}}}""".toByteArray()
        val result = FrameCodec.parse(plaintext)
        assertFalse(result.ok)
        assertEquals(FrameCodec.ERROR_PLAINTEXT_JSON, result.error)
        assertFalse(FrameCodec.looksFramed(plaintext))
        assertTrue(FrameCodec.looksPlaintextJson(plaintext))
        assertEquals(FrameCodec.ERROR_PLAINTEXT_JSON, result.classification())
    }

    @Test
    fun rejectsWhitespacePrefixedJson() {
        val result = FrameCodec.parse("  {\"a\":1}".toByteArray())
        assertFalse(result.ok)
        assertEquals(FrameCodec.ERROR_PLAINTEXT_JSON, result.error)
    }

    @Test
    fun rejectsTooShort() {
        val result = FrameCodec.parse(byteArrayOf(0xAA.toByte(), 0xAA.toByte(), 0x00))
        assertFalse(result.ok)
        assertEquals(FrameCodec.ERROR_TOO_SHORT, result.error)
    }

    @Test
    fun rejectsGarbage() {
        val result = FrameCodec.parse(byteArrayOf(0, 1, 2, 3, 4, 5))
        assertFalse(result.ok)
        assertEquals(FrameCodec.ERROR_NOT_FRAMED, result.error)
    }

    @Test
    fun rejectsTruncatedFramedBuffer() {
        val buffer = framedBuffer(414, 422).copyOfRange(0, 20)
        val result = FrameCodec.parse(buffer)
        assertFalse(result.ok)
        assertEquals(FrameCodec.ERROR_TRUNCATED, result.error)
        assertEquals(414, result.length)
        assertEquals(6, result.header.size)
    }

    @Test
    fun rejectsDeclaredLengthOverCap() {
        val buffer = byteArrayOf(0xAA.toByte(), 0xAA.toByte(), 0x00, 0x03, 0xFF.toByte(), 0xFF.toByte()) + ByteArray(8)
        val result = FrameCodec.parse(buffer)
        assertFalse(result.ok)
        assertEquals(FrameCodec.ERROR_INVALID_LENGTH, result.error)
        assertEquals(65535, result.length)
    }

    @Test
    fun headerBytesAreAaaa0003() {
        val hex = framedBuffer(222, 230).toHexSpaced().take(11)
        assertEquals("AA AA 00 03", hex)
    }

    private fun framedBuffer(declared: Int, total: Int): ByteArray {
        require(total == declared + FrameCodec.LENGTH_ENVELOPE)
        val buffer = ByteArray(total)
        FrameCodec.MAGIC.copyInto(buffer)
        buffer[4] = ((declared shr 8) and 0xFF).toByte()
        buffer[5] = (declared and 0xFF).toByte()
        return buffer
    }
}

class CaptureStoreTest {
    @Test
    fun boundsRetainedFramesAndExportsClassification() {
        val store = CaptureStore(maxFrames = 3)
        repeat(5) { index ->
            store.add(framed(230, 222), 1_000L + index)
        }
        assertEquals(5, store.packetCount)
        assertEquals(3, store.snapshot().size)
        assertEquals(5, store.snapshot().last().sequence)
        val export = store.exportText(mapOf("decode" to "locked"))
        assertTrue(export.contains("UNAVAILABLE"))
        assertTrue(export.contains("complete"))
        assertFalse(export.contains("temp"))
        assertFalse(export.contains("humidity"))
    }

    @Test
    fun classifiesPlaintextWithoutClaimingSensors() {
        val store = CaptureStore()
        val frame = store.add("""{"method":"getDevSta"}""".toByteArray(), 0L)
        assertEquals(FrameCodec.ERROR_PLAINTEXT_JSON, frame.classification)
        assertNull(frame.declaredLength)
    }

    private fun framed(total: Int, declared: Int): ByteArray {
        val buffer = ByteArray(total)
        FrameCodec.MAGIC.copyInto(buffer)
        buffer[4] = ((declared shr 8) and 0xFF).toByte()
        buffer[5] = (declared and 0xFF).toByte()
        return buffer
    }
}

class BleWriteGuardTest {
    @Test
    fun clientSourceNeverWritesCharacteristicsOrFf02() {
        val root = File("src/main/java/dev/verdant/ggsmonitor")
        assertTrue(root.isDirectory)
        val sources = root.walkTopDown().filter { it.extension == "kt" }.toList()
        assertTrue(sources.isNotEmpty())
        val ble = File(root, "GgsBleClient.kt").readText()
        assertFalse(ble.contains("writeCharacteristic("))
        assertFalse(ble.contains("getCharacteristic(FF02_UUID)"))
        assertTrue(ble.contains("0000ff01-0000-1000-8000-00805f9b34fb"))
        assertTrue(ble.contains("writeDescriptor"))
        assertTrue(ble.contains("never writeCharacteristic"))
        assertNotNull(GgsBleClient.FF02_UUID)
    }
}
