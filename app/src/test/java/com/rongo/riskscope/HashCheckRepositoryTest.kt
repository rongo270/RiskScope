package com.rongo.riskscope

import com.rongo.riskscope.network.HashCheckRepository
import org.junit.Assert.assertEquals
import org.junit.Test

class HashCheckRepositoryTest {

    @Test fun `adds https scheme and trailing slash`() {
        assertEquals("https://x.onrender.com/", HashCheckRepository.normalizeBaseUrl("x.onrender.com"))
    }

    @Test fun `keeps explicit http scheme for local dev`() {
        assertEquals("http://10.0.2.2:5000/", HashCheckRepository.normalizeBaseUrl("http://10.0.2.2:5000"))
    }

    @Test fun `keeps existing trailing slash`() {
        assertEquals("https://x.onrender.com/", HashCheckRepository.normalizeBaseUrl("https://x.onrender.com/"))
    }

    @Test fun `trims whitespace`() {
        assertEquals("https://x.onrender.com/", HashCheckRepository.normalizeBaseUrl("  https://x.onrender.com  "))
    }
}
