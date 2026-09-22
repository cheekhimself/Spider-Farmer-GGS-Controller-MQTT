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

    @Test
    fun exportContainsCompleteSectionAndMtuMeta() {
        val store = CaptureStore()
        val live = loadLive54()
        store.add(live, 1_700_000_000_000L)
        val export = store.exportText(
            mapOf(
                "negotiated_mtu" to "517",
                "decode" to "locked_unproven_vendor_key",
            ),
        )
        assertTrue(export.contains("# --- COMPLETE reassembled frames ---"))
        assertTrue(export.contains("# --- RAW notifies ---"))
        assertTrue(export.contains("complete_reassembled=1"))
        assertTrue(export.contains("negotiated_mtu: 517"))
        assertEquals(1, store.completeCount)
        assertEquals(54, store.completeSnapshot().single().observedLength)
        assertTrue(store.completeSnapshot().single().crcOk == true)
        assertFalse(export.contains("humidity"))
        assertFalse(export.contains("VPD"))
        assertFalse(export.contains("decrypt"))
    }

    @Test
    fun twentyByteHeadersDoNotInventCompleteFrames() {
        val store = CaptureStore()
        val headers = listOf(
            "AAAA0003019E000201BD00000410000000000190",
            "AAAA0003019E000201BD00000410000001900190",
            "AAAA000300FE000201BD000004100000032000F0",
        )
        headers.forEachIndexed { index, hex ->
            store.add(hexToBytes(hex), 1_000L + index)
        }
        assertEquals(3, store.packetCount)
        assertEquals(0, store.completeCount)
        store.snapshot().forEach { frame ->
            assertEquals(20, frame.observedLength)
            assertEquals(FrameCodec.ERROR_TRUNCATED, frame.classification)
        }
        val export = store.exportText(mapOf("negotiated_mtu" to "23"))
        assertTrue(export.contains("COMPLETE: none (no COMPLETE reassembled)"))
        assertTrue(export.contains("# (none)"))
    }

    private fun framed(total: Int, declared: Int): ByteArray {
        val buffer = ByteArray(total)
        FrameCodec.MAGIC.copyInto(buffer)
        buffer[4] = ((declared shr 8) and 0xFF).toByte()
        buffer[5] = (declared and 0xFF).toByte()
        return buffer
    }
}

class Crc16AndAssemblerTest {
    @Test
    fun livePhase3FiftyFourByteFramePassesModbusTrailer() {
        val live = loadLive54()
        assertEquals(54, live.size)
        assertTrue(FrameCodec.looksFramed(live))
        val parsed = FrameCodec.parse(live)
        assertTrue(parsed.ok)
        assertEquals(46, parsed.length)
        assertTrue(Crc16.trailerMatches(live))
        assertEquals(FrameCodec.CLASS_COMPLETE, parsed.classification())
    }

    @Test
    fun syntheticLengthCompleteWithoutTrailerIsCrcMismatch() {
        val buffer = ByteArray(230)
        FrameCodec.MAGIC.copyInto(buffer)
        buffer[4] = 0x00
        buffer[5] = 0xDE.toByte()
        assertTrue(FrameCodec.parse(buffer).ok)
        assertFalse(Crc16.trailerMatches(buffer))
        val assembler = FrameAssembler()
        val out = assembler.push(buffer)
        assertEquals(1, out.size)
        assertEquals(FrameCodec.CLASS_CRC_MISMATCH, out[0].classification)
        assertFalse(out[0].crcOk)
    }

    @Test
    fun reassemblesAttFragmentsIntoCrcCheckedComplete() {
        val live = loadLive54()
        val chunks = live.toList().chunked(20).map { it.toByteArray() }
        assertTrue(chunks.size > 1)
        assertTrue(FrameCodec.looksFramed(chunks.first()))
        assertFalse(FrameCodec.looksFramed(chunks[1]))
        val assembler = FrameAssembler()
        val emitted = ArrayList<AssembledFrame>()
        chunks.dropLast(1).forEach { chunk ->
            emitted.addAll(assembler.push(chunk))
        }
        assertTrue(emitted.isEmpty())
        emitted.addAll(assembler.push(chunks.last()))
        assertEquals(1, emitted.size)
        assertTrue(emitted[0].crcOk)
        assertEquals(FrameCodec.CLASS_COMPLETE, emitted[0].classification)
        assertTrue(emitted[0].bytes.contentEquals(live))
    }

    @Test
    fun magicStartingNotifiesDoNotConcatenateHeaders() {
        val assembler = FrameAssembler()
        val a = hexToBytes("AAAA0003019E000201BD00000410000000000190")
        val b = hexToBytes("AAAA0003019E000201BD00000410000001900190")
        assertTrue(assembler.push(a).isEmpty())
        assertTrue(assembler.push(b).isEmpty())
        assertEquals(20, assembler.pendingBytes())
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
        sources.forEach { file ->
            val text = file.readText()
            assertFalse("${file.name} must not write characteristics", text.contains("writeCharacteristic("))
        }
    }

    @Test
    fun clientRequestsPreferredMtuAfterServicesDiscovered() {
        val ble = File("src/main/java/dev/verdant/ggsmonitor/GgsBleClient.kt").readText()
        assertEquals(517, GgsBleClient.PREFERRED_MTU)
        assertTrue(ble.contains("requestMtu(PREFERRED_MTU)"))
        assertTrue(ble.contains("override fun onMtuChanged"))
        assertTrue(ble.contains("onServicesDiscovered"))
        val mtuIndex = ble.indexOf("gatt.requestMtu(PREFERRED_MTU)")
        val subIndex = ble.indexOf("private fun subscribeFf01")
        assertTrue(mtuIndex > 0)
        assertTrue(subIndex > mtuIndex)
        assertTrue(ble.contains("never writeCharacteristic"))
    }
}

private fun loadLive54(): ByteArray {
    val stream = FrameCodecTest::class.java.getResourceAsStream("/live_phase3_0003_54b.hex")
    assertNotNull(stream)
    val hex = stream!!.bufferedReader().readText()
    return hexToBytes(hex)
}

private fun hexToBytes(hex: String): ByteArray {
    val compact = hex.filter { !it.isWhitespace() }
    require(compact.length % 2 == 0)
    return ByteArray(compact.length / 2) { index ->
        compact.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
}

