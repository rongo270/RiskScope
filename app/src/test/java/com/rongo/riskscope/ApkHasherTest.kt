package com.rongo.riskscope

import com.rongo.riskscope.scan.ApkHasher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ApkHasherTest {

    @get:Rule val tmp = TemporaryFolder()

    @Test fun `bytesToHex is lowercase and correct`() {
        assertEquals("00ff10", ApkHasher.bytesToHex(byteArrayOf(0, 0xFF.toByte(), 0x10)))
    }

    @Test fun `sha256 of empty file matches known digest`() {
        val f = tmp.newFile("empty.apk")
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ApkHasher.sha256(f.absolutePath),
        )
    }

    @Test fun `sha256 of abc matches known digest`() {
        val f = tmp.newFile("abc.apk")
        f.writeText("abc")
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ApkHasher.sha256(f.absolutePath),
        )
    }

    @Test fun `missing or null path returns null`() {
        assertNull(ApkHasher.sha256(null))
        assertNull(ApkHasher.sha256("/no/such/file.apk"))
    }
}
