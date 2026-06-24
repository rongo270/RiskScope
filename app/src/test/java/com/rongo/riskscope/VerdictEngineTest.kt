package com.rongo.riskscope

import com.rongo.riskscope.model.RiskFinding
import com.rongo.riskscope.model.ServerVerdict
import com.rongo.riskscope.model.Severity
import com.rongo.riskscope.model.ThreatLevel
import com.rongo.riskscope.scan.ScannedApp
import com.rongo.riskscope.scan.VerdictEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VerdictEngineTest {

    private fun scanned(
        pkg: String = "com.example.app",
        trusted: Boolean = false,
        system: Boolean = false,
        debug: Boolean = false,
        score: Int = 0,
        findings: List<RiskFinding> = emptyList(),
        sha: String? = "ab".repeat(32),
    ) = ScannedApp(
        label = pkg, packageName = pkg, versionName = "1.0", apkSha256 = sha,
        certificateSha256 = "cert", debugCertificate = debug, installSource = "src",
        trustedInstaller = trusted, isSystemApp = system, enabled = true, hasLauncher = true,
        firstInstallTime = 0, lastUpdateTime = 0, heuristicScore = score, findings = findings,
        dangerousPermissions = emptyList(), grantedDangerousPermissions = emptyList(), icon = null,
    )

    private fun malware(family: String = "Anubis") = ServerVerdict(
        isMalicious = true, matchType = "sha256", source = "MalwareBazaar",
        sources = listOf("MalwareBazaar"), signature = family, fileType = "apk",
        explanation = "Known malware sample.",
    )

    private fun clean() = ServerVerdict(
        isMalicious = false, matchType = "none", source = null, sources = emptyList(),
        signature = null, fileType = null, explanation = "Not found.",
    )

    private val highFinding = RiskFinding(Severity.HIGH, "Accessibility service enabled", "…", 25)
    private val lowFinding = RiskFinding(Severity.LOW, "Location access requested", "…", 5)

    @Test fun `server malware is always DANGER even for trusted store apps`() {
        assertEquals(ThreatLevel.DANGER, VerdictEngine.classify(scanned(trusted = true), malware()))
    }

    @Test fun `trusted-store app with no malware match is SAFE`() {
        // The old behaviour wrongly flagged these; now they are clean.
        assertEquals(ThreatLevel.SAFE,
            VerdictEngine.classify(scanned(trusted = true, score = 90, findings = listOf(highFinding)), clean()))
    }

    @Test fun `system app is SAFE regardless of heuristics`() {
        assertEquals(ThreatLevel.SAFE,
            VerdictEngine.classify(scanned(system = true, score = 80, findings = listOf(highFinding)), null))
    }

    @Test fun `sideloaded app with debug cert is WATCH`() {
        assertEquals(ThreatLevel.WATCH, VerdictEngine.classify(scanned(debug = true), clean()))
    }

    @Test fun `sideloaded app with a HIGH finding is WATCH`() {
        assertEquals(ThreatLevel.WATCH,
            VerdictEngine.classify(scanned(findings = listOf(highFinding)), clean()))
    }

    @Test fun `sideloaded app with high heuristic score is WATCH`() {
        assertEquals(ThreatLevel.WATCH, VerdictEngine.classify(scanned(score = 50), null))
    }

    @Test fun `sideloaded normal app is SAFE`() {
        assertEquals(ThreatLevel.SAFE,
            VerdictEngine.classify(scanned(score = 10, findings = listOf(lowFinding)), clean()))
    }

    @Test fun `danger reason includes malware family`() {
        val app = VerdictEngine.finalize(scanned(), malware("Cerberus"))
        assertEquals(ThreatLevel.DANGER, app.threatLevel)
        assertTrue(app.reason.contains("Cerberus"))
    }

    @Test fun `summary counts and sort put threats first`() {
        val danger = VerdictEngine.finalize(scanned(pkg = "bad"), malware())
        val safe = VerdictEngine.finalize(scanned(pkg = "good", trusted = true), clean())
        val watch = VerdictEngine.finalize(scanned(pkg = "mid", findings = listOf(highFinding)), clean())

        val result = VerdictEngine.buildResult(listOf(safe, watch, danger), 1000, serverReachable = true)
        assertEquals(3, result.summary.scannedCount)
        assertEquals(1, result.summary.dangerCount)
        assertEquals(1, result.summary.watchCount)
        assertEquals(1, result.summary.safeCount)
        assertEquals(ThreatLevel.DANGER, result.apps.first().threatLevel) // sorted: threats on top
    }
}
