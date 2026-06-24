package com.rongo.riskscope.scan

import com.rongo.riskscope.model.AppRisk
import com.rongo.riskscope.model.DeviceSummary
import com.rongo.riskscope.model.ScanResult
import com.rongo.riskscope.model.ServerVerdict
import com.rongo.riskscope.model.Severity
import com.rongo.riskscope.model.ThreatLevel

/**
 * Combines the authoritative server hash verdict with the advisory on-device
 * heuristics into a single [ThreatLevel].
 *
 * Design goal (the whole point of the rewrite): NORMAL apps must not be flagged.
 *  - DANGER  only when the APK hash is a confirmed malware sample.
 *  - System apps and apps from a trusted store (Play, Galaxy Store, …) are SAFE
 *    no matter how many permissions they request — that was the old false alarm.
 *  - WATCH only for SIDELOADED apps that also show a genuinely notable signal
 *    (debug cert, active accessibility/admin, hidden startup, strong combos…).
 */
object VerdictEngine {

    /** Heuristic score above which a sideloaded app is worth a manual review. */
    private const val WATCH_SCORE_THRESHOLD = 35

    fun finalize(app: ScannedApp, verdict: ServerVerdict?): AppRisk {
        val level = classify(app, verdict)
        return AppRisk(
            label = app.label,
            packageName = app.packageName,
            versionName = app.versionName,
            apkSha256 = app.apkSha256,
            certificateSha256 = app.certificateSha256,
            installSource = app.installSource,
            trustedInstaller = app.trustedInstaller,
            isSystemApp = app.isSystemApp,
            enabled = app.enabled,
            hasLauncher = app.hasLauncher,
            firstInstallTime = app.firstInstallTime,
            lastUpdateTime = app.lastUpdateTime,
            heuristicScore = app.heuristicScore,
            findings = app.findings,
            dangerousPermissions = app.dangerousPermissions,
            grantedDangerousPermissions = app.grantedDangerousPermissions,
            serverVerdict = verdict,
            threatLevel = level,
            reason = reason(app, verdict, level),
            icon = app.icon,
        )
    }

    fun classify(app: ScannedApp, verdict: ServerVerdict?): ThreatLevel {
        if (verdict?.isMalicious == true) return ThreatLevel.DANGER
        // OEM/system and trusted-store apps are trusted unless hash-confirmed bad.
        if (app.isSystemApp || app.trustedInstaller) return ThreatLevel.SAFE
        return if (isNotable(app)) ThreatLevel.WATCH else ThreatLevel.SAFE
    }

    /** Strong, sideload-specific signals that justify a (non-alarming) review prompt. */
    private fun isNotable(app: ScannedApp): Boolean {
        if (app.debugCertificate) return true
        if (app.findings.any { it.severity == Severity.HIGH }) return true
        return app.heuristicScore >= WATCH_SCORE_THRESHOLD
    }

    private fun reason(app: ScannedApp, verdict: ServerVerdict?, level: ThreatLevel): String = when (level) {
        ThreatLevel.DANGER -> {
            val fam = verdict?.signature?.takeIf { it.isNotBlank() }
            val src = verdict?.source?.takeIf { it.isNotBlank() }
            buildString {
                append("Known malware")
                if (fam != null) append(" · $fam")
                if (src != null) append(" · $src")
            }
        }
        ThreatLevel.WATCH -> {
            val top = app.findings.firstOrNull()?.title
            buildString {
                append("Sideloaded")
                if (top != null) append(" · $top")
            }
        }
        ThreatLevel.SAFE -> when {
            app.isSystemApp -> "System app"
            app.trustedInstaller -> "From a trusted store"
            verdict != null -> "No known malware"
            app.apkSha256 == null -> "Not checked"
            else -> "Heuristics only (offline)"
        }
    }

    fun summarize(apps: List<AppRisk>, scanMillis: Long, serverReachable: Boolean): DeviceSummary {
        val danger = apps.count { it.threatLevel == ThreatLevel.DANGER }
        val watch = apps.count { it.threatLevel == ThreatLevel.WATCH }
        val safe = apps.count { it.threatLevel == ThreatLevel.SAFE }
        val hashed = apps.count { it.apkSha256 != null }
        return DeviceSummary(
            scannedCount = apps.size,
            hashedCount = hashed,
            dangerCount = danger,
            watchCount = watch,
            safeCount = safe,
            scanMillis = scanMillis,
            serverReachable = serverReachable,
        )
    }

    /** Sort: threats first, then watch, then by heuristic score, then name. */
    fun sort(apps: List<AppRisk>): List<AppRisk> = apps.sortedWith(
        compareByDescending<AppRisk> { it.threatLevel.ordinal }
            .thenByDescending { it.heuristicScore }
            .thenBy { it.label.lowercase() }
    )

    fun buildResult(apps: List<AppRisk>, scanMillis: Long, serverReachable: Boolean): ScanResult {
        val sorted = sort(apps)
        return ScanResult(summarize(sorted, scanMillis, serverReachable), sorted)
    }
}
