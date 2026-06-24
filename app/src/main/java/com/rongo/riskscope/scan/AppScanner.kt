package com.rongo.riskscope.scan

import android.Manifest
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.content.pm.Signature
import android.graphics.drawable.Drawable
import android.os.Build
import android.provider.Settings
import com.rongo.riskscope.model.RiskFinding
import com.rongo.riskscope.model.Severity
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

/** Intermediate per-app data produced by the scanner, before the server verdict is merged. */
data class ScannedApp(
    val label: String,
    val packageName: String,
    val versionName: String,
    val apkSha256: String?,
    val certificateSha256: String,
    val debugCertificate: Boolean,
    val installSource: String,
    val trustedInstaller: Boolean,
    val isSystemApp: Boolean,
    val enabled: Boolean,
    val hasLauncher: Boolean,
    val firstInstallTime: Long,
    val lastUpdateTime: Long,
    val heuristicScore: Int,
    val findings: List<RiskFinding>,
    val dangerousPermissions: List<String>,
    val grantedDangerousPermissions: List<String>,
    val icon: Drawable?,
)

/**
 * Enumerates installed apps, computes each APK's SHA-256, and runs lightweight
 * behavioural heuristics (ported from the original RiskAnalyzer). The heuristics
 * are advisory only — the authoritative "is this malware?" answer comes from the
 * server hash check.
 */
@Suppress("DEPRECATION") // legacy PackageManager flag/signature APIs used on older SDKs
class AppScanner(context: Context) {

    private val context = context.applicationContext
    private val pm: PackageManager = this.context.packageManager

    fun scan(
        includeSystemApps: Boolean,
        onProgress: (done: Int, total: Int) -> Unit = { _, _ -> },
    ): List<ScannedApp> {
        val launcherPackages = queryLauncherPackages()
        val bootPackages = queryBootReceiverPackages()
        val enabledAccessibility = readEnabledAccessibilityComponents()
        val activeAdmins = readActiveAdminPackages()

        val packages = installedPackages()
        val total = packages.size
        val out = ArrayList<ScannedApp>(total)
        packages.forEachIndexed { index, info ->
            val appInfo = info.applicationInfo
            if (appInfo != null) {
                out += analyze(info, appInfo, includeSystemApps, launcherPackages,
                    bootPackages, enabledAccessibility, activeAdmins)
            }
            onProgress(index + 1, total)
        }
        return out
    }

    private fun analyze(
        info: PackageInfo,
        appInfo: ApplicationInfo,
        includeSystemApps: Boolean,
        launcherPackages: Set<String>,
        bootPackages: Set<String>,
        enabledAccessibility: Set<String>,
        activeAdmins: Set<String>,
    ): ScannedApp {
        val packageName = info.packageName
        val systemApp = isSystemApp(appInfo)
        val hasLauncher = packageName in launcherPackages
        val startsAtBoot = packageName in bootPackages

        val install = readInstallSource(packageName, systemApp)
        val signature = readSignatureState(info)

        val findings = ArrayList<RiskFinding>()
        val requestedDangerous = ArrayList<String>()
        val grantedDangerous = ArrayList<String>()
        val requested = readRequestedPermissions(info, requestedDangerous, grantedDangerous)

        var score = 0
        val hasSms = requested.any { it in SMS_PERMISSIONS }
        val hasContacts = requested.any { it in CONTACT_PERMISSIONS }
        val hasLocation = requested.any { it in LOCATION_PERMISSIONS }
        val hasBackgroundLocation = Manifest.permission.ACCESS_BACKGROUND_LOCATION in requested
        val hasCallLog = requested.any { it in CALL_LOG_PERMISSIONS }

        if (!install.trusted && !systemApp) {
            score += if (install.unknown)
                add(findings, Severity.MEDIUM, "Unknown install source",
                    "Android did not report which installer placed this app.", 12)
            else
                add(findings, Severity.HIGH, "Installed outside a recognized store",
                    "Installer package: ${install.installerPackage}", 18)
        }

        if (!signature.available) {
            score += add(findings, Severity.MEDIUM, "Signing certificate unavailable",
                "The app signature could not be read.", 10)
        } else if (signature.debugCertificate) {
            score += add(findings, Severity.HIGH, "Debug signing certificate",
                "Signed with an Android debug/test certificate (never true for Play Store apps).", 22)
        }
        if (signature.multipleSigners) {
            score += add(findings, Severity.LOW, "Multiple APK signers",
                "Multiple signing certificates were reported.", 4)
        }

        if (requestedDangerous.isNotEmpty()) {
            val weight = minOf(if (systemApp) 8 else 18,
                requestedDangerous.size * 2 + grantedDangerous.size)
            val severity = if (requestedDangerous.size >= 8) Severity.MEDIUM else Severity.LOW
            score += add(findings, severity, "Broad dangerous permission surface",
                "${requestedDangerous.size} dangerous permissions requested; ${grantedDangerous.size} granted.", weight)
        }
        if (hasSms) score += add(findings, Severity.HIGH, "SMS access requested",
            "SMS permissions can expose one-time codes and private messages.", 14)
        if (hasContacts) score += add(findings, Severity.MEDIUM, "Contacts access requested",
            "Contact permissions expose the user's social graph.", 9)
        if (hasBackgroundLocation) score += add(findings, Severity.HIGH, "Background location requested",
            "Allows location collection when the app is not visible.", 16)
        else if (hasLocation) score += add(findings, Severity.LOW, "Location access requested",
            "Foreground location permissions are present.", 5)
        if (hasCallLog) score += add(findings, Severity.MEDIUM, "Phone or call-log access requested",
            "Phone state and call-log permissions are sensitive metadata.", 9)

        val requestsOverlay = Manifest.permission.SYSTEM_ALERT_WINDOW in requested
        val overlayAllowed = requestsOverlay && isOverlayAllowed(appInfo)
        if (overlayAllowed) score += add(findings, Severity.HIGH, "Overlay permission allowed",
            "The app can draw over other apps — often abused for phishing overlays.", 20)
        else if (requestsOverlay) score += add(findings, Severity.MEDIUM, "Overlay permission requested",
            "The app declares SYSTEM_ALERT_WINDOW.", 8)

        val services = inspectServices(info, enabledAccessibility)
        if (services.enabledAccessibility > 0) score += add(findings, Severity.HIGH,
            "Accessibility service enabled", "Enabled accessibility can observe and control other apps.", 25)
        else if (services.declaredAccessibility > 0) score += add(findings, Severity.MEDIUM,
            "Accessibility service declared", "The app contains an accessibility service component.", 8)
        if (services.notificationListeners > 0) score += add(findings, Severity.MEDIUM,
            "Notification listener declared", "Can read notification contents after approval.", 8)

        val adminActive = packageName in activeAdmins
        if (adminActive) score += add(findings, Severity.HIGH, "Device admin active",
            "The app currently holds Device Admin privileges.", 24)

        if (Manifest.permission.REQUEST_INSTALL_PACKAGES in requested)
            score += add(findings, Severity.MEDIUM, "Can request APK installs",
                "REQUEST_INSTALL_PACKAGES lets it prompt to install other APKs.", 12)
        if (PERMISSION_USAGE_STATS in requested)
            score += add(findings, Severity.MEDIUM, "Usage access requested",
                "Usage access can reveal app-usage history if granted.", 10)

        if (startsAtBoot && !systemApp)
            score += add(findings, Severity.LOW, "Starts automatically",
                "Registers for boot-completed startup broadcasts.", 6)
        if (!hasLauncher && !systemApp && appInfo.enabled)
            score += add(findings, Severity.MEDIUM, "No launcher entry",
                "A user-installed enabled app with no visible launcher icon.", 12)

        // High-risk combinations.
        if (hasSms && hasContacts) score += add(findings, Severity.HIGH, "SMS and contacts combination",
            "Useful for account takeover and social targeting.", 14)
        if ((hasSms || hasContacts || hasBackgroundLocation) && overlayAllowed)
            score += add(findings, Severity.HIGH, "Sensitive data with overlay",
                "Overlay access plus sensitive permissions increases phishing risk.", 14)
        if ((hasSms || hasContacts) && services.enabledAccessibility > 0)
            score += add(findings, Severity.HIGH, "Sensitive data with accessibility",
                "Accessibility plus sensitive permissions is a high-risk combination.", 18)
        if (!hasLauncher && startsAtBoot && !systemApp)
            score += add(findings, Severity.HIGH, "Hidden startup behavior",
                "No launcher entry but can start after boot.", 15)

        findings.sortWith(compareByDescending<RiskFinding> { it.weight }.thenBy { it.title })

        // Only hash apps we actually want a server verdict for (skip the many OEM
        // system apps unless requested — keeps scans fast and avoids huge I/O).
        val shouldHash = includeSystemApps || !systemApp
        val apkSha256 = if (shouldHash) ApkHasher.sha256(appInfo.sourceDir) else null

        return ScannedApp(
            label = readLabel(appInfo, packageName),
            packageName = packageName,
            versionName = info.versionName ?: "Unknown",
            apkSha256 = apkSha256,
            certificateSha256 = signature.sha256,
            debugCertificate = signature.debugCertificate,
            installSource = install.display,
            trustedInstaller = install.trusted,
            isSystemApp = systemApp,
            enabled = appInfo.enabled,
            hasLauncher = hasLauncher,
            firstInstallTime = info.firstInstallTime,
            lastUpdateTime = info.lastUpdateTime,
            heuristicScore = score.coerceIn(0, 100),
            findings = findings,
            dangerousPermissions = requestedDangerous.sorted(),
            grantedDangerousPermissions = grantedDangerous.sorted(),
            icon = readIcon(appInfo),
        )
    }

    // ── Permissions ───────────────────────────────────────────────

    private fun readRequestedPermissions(
        info: PackageInfo, requestedDangerous: MutableList<String>, grantedDangerous: MutableList<String>,
    ): Set<String> {
        val requested = HashSet<String>()
        val perms = info.requestedPermissions ?: return requested
        val flags = info.requestedPermissionsFlags
        perms.forEachIndexed { i, permission ->
            if (permission == null) return@forEachIndexed
            requested += permission
            if (isDangerous(permission)) {
                requestedDangerous += permission
                val granted = flags != null && i < flags.size &&
                    (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                if (granted) grantedDangerous += permission
            }
        }
        return requested
    }

    private fun isDangerous(permission: String): Boolean = try {
        val info = pm.getPermissionInfo(permission, 0)
        (info.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE) == PermissionInfo.PROTECTION_DANGEROUS
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    // ── Services / admin / overlay ─────────────────────────────────

    private data class ServiceSignals(
        var declaredAccessibility: Int = 0,
        var enabledAccessibility: Int = 0,
        var notificationListeners: Int = 0,
    )

    private fun inspectServices(info: PackageInfo, enabledAccessibility: Set<String>): ServiceSignals {
        val signals = ServiceSignals()
        val services = info.services ?: return signals
        for (service in services) {
            when (service?.permission) {
                BIND_ACCESSIBILITY -> {
                    signals.declaredAccessibility++
                    val component = ComponentName(service.packageName, service.name)
                    if (component.flattenToString() in enabledAccessibility ||
                        component.flattenToShortString() in enabledAccessibility
                    ) signals.enabledAccessibility++
                }
                BIND_NOTIFICATION_LISTENER -> signals.notificationListeners++
            }
        }
        return signals
    }

    private fun isOverlayAllowed(appInfo: ApplicationInfo): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager ?: return false
        return try {
            val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, appInfo.uid, appInfo.packageName)
            else
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, appInfo.uid, appInfo.packageName)
            mode == AppOpsManager.MODE_ALLOWED || mode == AppOpsManager.MODE_FOREGROUND
        } catch (e: Exception) {
            false
        }
    }

    private fun readActiveAdminPackages(): Set<String> {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
            ?: return emptySet()
        return try {
            dpm.activeAdmins?.map { it.packageName }?.toSet() ?: emptySet()
        } catch (e: SecurityException) {
            emptySet()
        }
    }

    private fun readEnabledAccessibilityComponents(): Set<String> {
        val enabled = Settings.Secure.getString(
            context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return emptySet()
        return enabled.split(':').filter { it.isNotBlank() }.toSet()
    }

    // ── Install source / signatures ────────────────────────────────

    private data class InstallSource(
        val installerPackage: String?, val display: String,
        val trusted: Boolean, val unknown: Boolean,
    )

    private fun readInstallSource(packageName: String, systemApp: Boolean): InstallSource {
        if (systemApp) return InstallSource(null, "System image or OEM update", true, false)
        var installer: String? = null
        try {
            installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val src = pm.getInstallSourceInfo(packageName)
                src.installingPackageName ?: src.initiatingPackageName
            } else {
                pm.getInstallerPackageName(packageName)
            }
        } catch (e: Exception) {
            installer = null
        }
        val unknown = installer.isNullOrEmpty()
        val trusted = !unknown && installer in TRUSTED_INSTALLERS
        val display = if (unknown) "Installer: unknown"
        else "Installer: ${readPackageLabel(installer)} ($installer)"
        return InstallSource(installer, display, trusted, unknown)
    }

    private data class SignatureState(
        val available: Boolean, val debugCertificate: Boolean,
        val multipleSigners: Boolean, val sha256: String,
    )

    private fun readSignatureState(info: PackageInfo): SignatureState {
        val signatures = ArrayList<Signature>()
        var multipleSigners = false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = info.signingInfo
            if (signingInfo != null) {
                if (signingInfo.hasMultipleSigners()) {
                    multipleSigners = true
                    signingInfo.apkContentsSigners?.let { signatures.addAll(it.toList()) }
                } else {
                    signingInfo.signingCertificateHistory?.let { signatures.addAll(it.toList()) }
                }
            }
        } else {
            info.signatures?.let {
                signatures.addAll(it.toList())
                multipleSigners = it.size > 1
            }
        }
        if (signatures.isEmpty()) return SignatureState(false, false, false, "Unavailable")

        val sha256 = sha256Hex(signatures[0].toByteArray())
        val debug = signatures.any { isDebugCertificate(it) }
        return SignatureState(true, debug, multipleSigners, sha256)
    }

    private fun isDebugCertificate(signature: Signature): Boolean = try {
        val factory = CertificateFactory.getInstance("X.509")
        val cert = factory.generateCertificate(ByteArrayInputStream(signature.toByteArray())) as X509Certificate
        cert.subjectX500Principal.name?.lowercase(Locale.US)?.contains("android debug") == true
    } catch (e: Exception) {
        false
    }

    private fun sha256Hex(bytes: ByteArray): String = try {
        ApkHasher.bytesToHex(MessageDigest.getInstance("SHA-256").digest(bytes))
    } catch (e: Exception) {
        "Unavailable"
    }

    // ── PackageManager queries (handle old + new flag APIs) ────────

    private fun installedPackages(): List<PackageInfo> {
        var flags = (PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES
            or PackageManager.GET_RECEIVERS or PackageManager.GET_ACTIVITIES
            or PackageManager.MATCH_DISABLED_COMPONENTS).toLong()
        flags = flags or (
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
                PackageManager.GET_SIGNING_CERTIFICATES.toLong()
            else
                PackageManager.GET_SIGNATURES.toLong()
            )

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags))
        else
            pm.getInstalledPackages(flags.toInt())
    }

    private fun queryLauncherPackages(): Set<String> {
        val out = HashSet<String>()
        for (category in listOf(Intent.CATEGORY_LAUNCHER, Intent.CATEGORY_LEANBACK_LAUNCHER)) {
            val intent = Intent(Intent.ACTION_MAIN).addCategory(category)
            for (resolve in queryActivities(intent)) {
                resolve.activityInfo?.packageName?.let { out += it }
            }
        }
        return out
    }

    private fun queryBootReceiverPackages(): Set<String> {
        val out = HashSet<String>()
        val actions = listOf(
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_LOCKED_BOOT_COMPLETED,
            "android.intent.action.QUICKBOOT_POWERON",
        )
        for (action in actions) {
            for (resolve in queryReceivers(Intent(action))) {
                resolve.activityInfo?.packageName?.let { out += it }
            }
        }
        return out
    }

    private fun queryActivities(intent: Intent) =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0))
        else pm.queryIntentActivities(intent, 0)

    private fun queryReceivers(intent: Intent) =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            pm.queryBroadcastReceivers(intent, PackageManager.ResolveInfoFlags.of(0))
        else pm.queryBroadcastReceivers(intent, 0)

    private fun readLabel(appInfo: ApplicationInfo, fallback: String): String = try {
        pm.getApplicationLabel(appInfo).toString().ifBlank { fallback }
    } catch (e: Exception) {
        fallback
    }

    private fun readIcon(appInfo: ApplicationInfo): Drawable? = try {
        pm.getApplicationIcon(appInfo)
    } catch (e: Exception) {
        null
    }

    private fun readPackageLabel(packageName: String): String = try {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0))
        else pm.getApplicationInfo(packageName, 0)
        readLabel(info, packageName)
    } catch (e: PackageManager.NameNotFoundException) {
        packageName
    }

    private fun isSystemApp(appInfo: ApplicationInfo): Boolean =
        (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
            (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

    private fun add(list: MutableList<RiskFinding>, severity: Severity, title: String, detail: String, weight: Int): Int {
        list += RiskFinding(severity, title, detail, weight)
        return weight
    }

    companion object {
        private const val PERMISSION_USAGE_STATS = "android.permission.PACKAGE_USAGE_STATS"
        private const val BIND_ACCESSIBILITY = "android.permission.BIND_ACCESSIBILITY_SERVICE"
        private const val BIND_NOTIFICATION_LISTENER = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"

        private val TRUSTED_INSTALLERS = setOf(
            "com.android.vending", "com.google.android.feedback",
            "com.google.android.apps.work.oobconfig",
            "com.sec.android.app.samsungapps", "com.amazon.venezia",
            "com.huawei.appmarket", "com.xiaomi.mipicks",
            "com.oppo.market", "com.heytap.market", "com.vivo.appstore",
        )
        private val SMS_PERMISSIONS = setOf(
            Manifest.permission.READ_SMS, Manifest.permission.RECEIVE_SMS,
            Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_MMS,
            Manifest.permission.RECEIVE_WAP_PUSH, "android.permission.WRITE_SMS",
        )
        private val CONTACT_PERMISSIONS = setOf(
            Manifest.permission.READ_CONTACTS, Manifest.permission.WRITE_CONTACTS,
            Manifest.permission.GET_ACCOUNTS,
        )
        private val LOCATION_PERMISSIONS = setOf(
            Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_BACKGROUND_LOCATION,
        )
        private val CALL_LOG_PERMISSIONS = setOf(
            Manifest.permission.READ_CALL_LOG, Manifest.permission.WRITE_CALL_LOG,
            Manifest.permission.READ_PHONE_STATE, Manifest.permission.READ_PHONE_NUMBERS,
            Manifest.permission.CALL_PHONE,
        )
    }
}
