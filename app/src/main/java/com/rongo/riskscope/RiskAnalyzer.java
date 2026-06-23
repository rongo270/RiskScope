package com.rongo.riskscope;

import android.Manifest;
import android.app.AppOpsManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.graphics.drawable.Drawable;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class RiskAnalyzer {
    private static final String PERMISSION_PACKAGE_USAGE_STATS = "android.permission.PACKAGE_USAGE_STATS";
    private static final String PERMISSION_MANAGE_EXTERNAL_STORAGE = "android.permission.MANAGE_EXTERNAL_STORAGE";
    private static final String PERMISSION_BIND_ACCESSIBILITY = "android.permission.BIND_ACCESSIBILITY_SERVICE";
    private static final String PERMISSION_BIND_DEVICE_ADMIN = "android.permission.BIND_DEVICE_ADMIN";
    private static final String PERMISSION_BIND_VPN = "android.permission.BIND_VPN_SERVICE";
    private static final String PERMISSION_BIND_NOTIFICATION_LISTENER = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE";

    private static final Set<String> TRUSTED_INSTALLERS = setOf(
            "com.android.vending",
            "com.google.android.apps.work.oobconfig",
            "com.google.android.feedback",
            "com.sec.android.app.samsungapps",
            "com.amazon.venezia",
            "com.huawei.appmarket",
            "com.xiaomi.mipicks",
            "com.oppo.market",
            "com.heytap.market",
            "com.vivo.appstore"
    );

    private static final Set<String> SMS_PERMISSIONS = setOf(
            Manifest.permission.READ_SMS,
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.SEND_SMS,
            Manifest.permission.RECEIVE_MMS,
            Manifest.permission.RECEIVE_WAP_PUSH,
            "android.permission.WRITE_SMS"
    );

    private static final Set<String> CONTACT_PERMISSIONS = setOf(
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.WRITE_CONTACTS,
            Manifest.permission.GET_ACCOUNTS
    );

    private static final Set<String> LOCATION_PERMISSIONS = setOf(
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_BACKGROUND_LOCATION
    );

    private static final Set<String> CALL_LOG_PERMISSIONS = setOf(
            Manifest.permission.READ_CALL_LOG,
            Manifest.permission.WRITE_CALL_LOG,
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.READ_PHONE_NUMBERS,
            Manifest.permission.CALL_PHONE
    );

    private final Context context;

    public RiskAnalyzer(Context context) {
        this.context = context.getApplicationContext();
    }

    public RiskScanResult scan() {
        long startedAt = System.currentTimeMillis();
        PackageManager packageManager = context.getPackageManager();
        Set<String> launcherPackages = queryLauncherPackages(packageManager);
        Set<String> bootPackages = queryBootReceiverPackages(packageManager);
        Set<String> enabledAccessibilityComponents = readEnabledAccessibilityComponents();
        Set<String> activeAdminPackages = readActiveAdminPackages();
        boolean activeVpn = hasActiveVpn();
        String proxySummary = readProxySummary();

        List<AppRiskReport> reports = new ArrayList<>();
        for (PackageInfo packageInfo : getInstalledPackages(packageManager, packageInfoFlags())) {
            if (packageInfo == null || packageInfo.applicationInfo == null) {
                continue;
            }
            reports.add(analyzePackage(
                    packageManager,
                    packageInfo,
                    launcherPackages,
                    bootPackages,
                    enabledAccessibilityComponents,
                    activeAdminPackages
            ));
        }

        Collections.sort(reports, new Comparator<AppRiskReport>() {
            @Override
            public int compare(AppRiskReport left, AppRiskReport right) {
                int byRisk = Integer.compare(right.getRiskScore(), left.getRiskScore());
                if (byRisk != 0) {
                    return byRisk;
                }
                return left.getLabel().compareToIgnoreCase(right.getLabel());
            }
        });

        DeviceSecuritySnapshot snapshot = DeviceSecuritySnapshot.fromReports(
                reports,
                activeVpn,
                proxySummary,
                System.currentTimeMillis() - startedAt
        );
        return new RiskScanResult(snapshot, reports);
    }

    private AppRiskReport analyzePackage(
            PackageManager packageManager,
            PackageInfo packageInfo,
            Set<String> launcherPackages,
            Set<String> bootPackages,
            Set<String> enabledAccessibilityComponents,
            Set<String> activeAdminPackages
    ) {
        ApplicationInfo appInfo = packageInfo.applicationInfo;
        String packageName = packageInfo.packageName;
        boolean systemApp = isSystemApp(appInfo);
        boolean hasLauncher = launcherPackages.contains(packageName);
        boolean startsAtBoot = bootPackages.contains(packageName);
        InstallSource installSource = readInstallSource(packageManager, packageName, systemApp);
        SignatureState signatureState = readSignatureState(packageInfo);

        List<RiskFinding> findings = new ArrayList<>();
        List<String> requestedDangerousPermissions = new ArrayList<>();
        List<String> grantedDangerousPermissions = new ArrayList<>();
        Set<String> requestedPermissions = readRequestedPermissions(packageManager, packageInfo, requestedDangerousPermissions, grantedDangerousPermissions);

        int score = 0;
        boolean hasSms = hasAny(requestedPermissions, SMS_PERMISSIONS);
        boolean hasContacts = hasAny(requestedPermissions, CONTACT_PERMISSIONS);
        boolean hasLocation = hasAny(requestedPermissions, LOCATION_PERMISSIONS);
        boolean hasBackgroundLocation = requestedPermissions.contains(Manifest.permission.ACCESS_BACKGROUND_LOCATION);
        boolean hasCallLog = hasAny(requestedPermissions, CALL_LOG_PERMISSIONS);

        if (!installSource.trusted && !systemApp) {
            if (installSource.unknown) {
                score += add(findings, RiskFinding.Severity.MEDIUM, "Unknown install source", "Android did not expose the installer package for this user-installed app.", 12);
            } else {
                score += add(findings, RiskFinding.Severity.HIGH, "Installed outside a recognized store", "Installer package: " + installSource.installerPackage, 18);
            }
        }

        if (!signatureState.available) {
            score += add(findings, RiskFinding.Severity.MEDIUM, "Signing certificate unavailable", "The app signature could not be read through PackageManager.", 10);
        } else if (signatureState.debugCertificate) {
            score += add(findings, RiskFinding.Severity.HIGH, "Debug signing certificate", "The app appears to be signed with an Android debug/test certificate.", 22);
        } else if (!systemApp && !installSource.trusted) {
            score += add(findings, RiskFinding.Severity.LOW, "Verify certificate manually", "No offline reputation database is bundled; use the SHA-256 fingerprint in details for manual checks.", 3);
        }

        if (signatureState.multipleSigners) {
            score += add(findings, RiskFinding.Severity.LOW, "Multiple APK signers", "Multiple signing certificates were reported for the APK contents.", 4);
        }
        if (!requestedDangerousPermissions.isEmpty()) {
            int weight = Math.min(systemApp ? 8 : 18, requestedDangerousPermissions.size() * 2 + grantedDangerousPermissions.size());
            RiskFinding.Severity severity = requestedDangerousPermissions.size() >= 8 ? RiskFinding.Severity.MEDIUM : RiskFinding.Severity.LOW;
            score += add(findings, severity, "Broad dangerous permission surface", requestedDangerousPermissions.size() + " dangerous permissions requested; " + grantedDangerousPermissions.size() + " currently granted.", weight);
        }

        if (hasSms) {
            score += add(findings, RiskFinding.Severity.HIGH, "SMS access requested", "SMS permissions can expose one-time codes and private messages.", 14);
        }
        if (hasContacts) {
            score += add(findings, RiskFinding.Severity.MEDIUM, "Contacts access requested", "Contact permissions expose the user's social graph.", 9);
        }
        if (hasBackgroundLocation) {
            score += add(findings, RiskFinding.Severity.HIGH, "Background location requested", "Background location allows location collection when the app is not visible.", 16);
        } else if (hasLocation) {
            score += add(findings, RiskFinding.Severity.LOW, "Location access requested", "Foreground location permissions are present.", 5);
        }
        if (hasCallLog) {
            score += add(findings, RiskFinding.Severity.MEDIUM, "Phone or call-log access requested", "Phone state and call-log permissions are sensitive metadata.", 9);
        }

        boolean requestsOverlay = requestedPermissions.contains(Manifest.permission.SYSTEM_ALERT_WINDOW);
        boolean overlayAllowed = requestsOverlay && isOverlayAllowed(appInfo);
        if (overlayAllowed) {
            score += add(findings, RiskFinding.Severity.HIGH, "Overlay permission allowed", "The app can draw over other apps, which is often abused for phishing.", 20);
        } else if (requestsOverlay) {
            score += add(findings, RiskFinding.Severity.MEDIUM, "Overlay permission requested", "The app declares SYSTEM_ALERT_WINDOW.", 8);
        }

        ServiceSignals serviceSignals = inspectServices(packageInfo, enabledAccessibilityComponents);
        if (serviceSignals.enabledAccessibilityServices > 0) {
            score += add(findings, RiskFinding.Severity.HIGH, "Accessibility service enabled", "Enabled accessibility services can observe and control other apps.", 25);
        } else if (serviceSignals.declaredAccessibilityServices > 0) {
            score += add(findings, RiskFinding.Severity.MEDIUM, "Accessibility service declared", "The app contains an accessibility service component.", 8);
        }
        if (serviceSignals.vpnServices > 0) {
            score += add(findings, RiskFinding.Severity.LOW, "VPN service declared", "The app can provide a VPN tunnel if the user enables it.", 5);
        }
        if (serviceSignals.notificationListenerServices > 0) {
            score += add(findings, RiskFinding.Severity.MEDIUM, "Notification listener declared", "Notification listeners can read notification contents after user approval.", 8);
        }

        AdminSignals adminSignals = inspectDeviceAdmin(packageInfo, activeAdminPackages);
        if (adminSignals.activeAdmin) {
            score += add(findings, RiskFinding.Severity.HIGH, "Device admin active", "The app currently has Device Admin privileges.", 24);
        } else if (adminSignals.declaredAdmins > 0) {
            score += add(findings, RiskFinding.Severity.MEDIUM, "Device admin receiver declared", "The app can request Device Admin privileges.", 7);
        }

        if (requestedPermissions.contains(Manifest.permission.REQUEST_INSTALL_PACKAGES)) {
            score += add(findings, RiskFinding.Severity.MEDIUM, "Can request APK installs", "REQUEST_INSTALL_PACKAGES allows prompting the user to install other APKs.", 12);
        }
        if (requestedPermissions.contains(PERMISSION_PACKAGE_USAGE_STATS)) {
            score += add(findings, RiskFinding.Severity.MEDIUM, "Usage access requested", "Usage access can reveal app usage history if the user grants it.", 10);
        }
        if (requestedPermissions.contains(Manifest.permission.WRITE_SETTINGS)) {
            score += add(findings, RiskFinding.Severity.MEDIUM, "System settings write requested", "WRITE_SETTINGS can alter device behavior after user approval.", 8);
        }
        if (requestedPermissions.contains(PERMISSION_MANAGE_EXTERNAL_STORAGE)) {
            score += add(findings, RiskFinding.Severity.MEDIUM, "All-files access requested", "MANAGE_EXTERNAL_STORAGE grants broad file visibility when approved.", 10);
        }

        if (startsAtBoot && !systemApp) {
            int bootWeight = (hasSms || hasContacts || hasBackgroundLocation || overlayAllowed || adminSignals.activeAdmin || serviceSignals.enabledAccessibilityServices > 0) ? 12 : 6;
            score += add(findings, bootWeight >= 12 ? RiskFinding.Severity.MEDIUM : RiskFinding.Severity.LOW, "Starts automatically", "The app registers for boot-completed style startup broadcasts.", bootWeight);
        }

        if (!hasLauncher && !systemApp && appInfo.enabled) {
            score += add(findings, RiskFinding.Severity.MEDIUM, "No launcher entry", "A user-installed enabled app has no visible launcher activity.", 12);
        }

        if (hasSms && hasContacts) {
            score += add(findings, RiskFinding.Severity.HIGH, "SMS and contacts combination", "This combination is useful for account takeover and social targeting.", 14);
        }
        if (hasSms && hasBackgroundLocation) {
            score += add(findings, RiskFinding.Severity.HIGH, "SMS with background location", "Combines messaging data with persistent location access.", 16);
        }
        if ((hasSms || hasContacts || hasBackgroundLocation) && overlayAllowed) {
            score += add(findings, RiskFinding.Severity.HIGH, "Sensitive data with overlay", "Overlay access combined with sensitive permissions increases phishing risk.", 14);
        }
        if ((hasSms || hasContacts || hasBackgroundLocation) && serviceSignals.enabledAccessibilityServices > 0) {
            score += add(findings, RiskFinding.Severity.HIGH, "Sensitive data with accessibility", "Accessibility plus sensitive permissions is a high-risk combination.", 18);
        }
        if (adminSignals.activeAdmin && (hasSms || hasContacts || serviceSignals.enabledAccessibilityServices > 0 || overlayAllowed)) {
            score += add(findings, RiskFinding.Severity.HIGH, "Admin with invasive capabilities", "Device Admin combined with other invasive capabilities can make removal harder.", 18);
        }
        if (!hasLauncher && startsAtBoot && !systemApp) {
            score += add(findings, RiskFinding.Severity.HIGH, "Hidden startup behavior", "The app has no launcher entry but can start after boot.", 15);
        }

        if (systemApp && score > 0) {
            score = Math.max(0, score - Math.min(18, score / 3));
        }

        Collections.sort(findings, new Comparator<RiskFinding>() {
            @Override
            public int compare(RiskFinding left, RiskFinding right) {
                int byWeight = Integer.compare(right.getWeight(), left.getWeight());
                if (byWeight != 0) {
                    return byWeight;
                }
                return left.getTitle().compareToIgnoreCase(right.getTitle());
            }
        });

        return new AppRiskReport(
                readLabel(packageManager, appInfo, packageName),
                packageName,
                packageInfo.versionName == null ? "Unknown" : packageInfo.versionName,
                installSource.displayText,
                signatureState.summary,
                signatureState.primarySha256,
                packageInfo.firstInstallTime,
                packageInfo.lastUpdateTime,
                score,
                systemApp,
                appInfo.enabled,
                hasLauncher,
                readIcon(packageManager, appInfo),
                findings,
                requestedDangerousPermissions,
                grantedDangerousPermissions
        );
    }

    private Set<String> readRequestedPermissions(
            PackageManager packageManager,
            PackageInfo packageInfo,
            List<String> requestedDangerous,
            List<String> grantedDangerous
    ) {
        Set<String> requested = new HashSet<>();
        if (packageInfo.requestedPermissions == null) {
            return requested;
        }
        for (int i = 0; i < packageInfo.requestedPermissions.length; i++) {
            String permission = packageInfo.requestedPermissions[i];
            if (permission == null) {
                continue;
            }
            requested.add(permission);
            if (isDangerousPermission(packageManager, permission)) {
                requestedDangerous.add(permission);
                if (packageInfo.requestedPermissionsFlags != null
                        && i < packageInfo.requestedPermissionsFlags.length
                        && (packageInfo.requestedPermissionsFlags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) {
                    grantedDangerous.add(permission);
                }
            }
        }
        Collections.sort(requestedDangerous);
        Collections.sort(grantedDangerous);
        return requested;
    }

    private boolean isDangerousPermission(PackageManager packageManager, String permission) {
        try {
            PermissionInfo info = packageManager.getPermissionInfo(permission, 0);
            return (info.protectionLevel & PermissionInfo.PROTECTION_MASK_BASE) == PermissionInfo.PROTECTION_DANGEROUS;
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }

    private ServiceSignals inspectServices(PackageInfo packageInfo, Set<String> enabledAccessibilityComponents) {
        ServiceSignals signals = new ServiceSignals();
        if (packageInfo.services == null) {
            return signals;
        }
        for (ServiceInfo service : packageInfo.services) {
            if (service == null || service.permission == null) {
                continue;
            }
            if (PERMISSION_BIND_ACCESSIBILITY.equals(service.permission)) {
                signals.declaredAccessibilityServices++;
                ComponentName componentName = new ComponentName(service.packageName, service.name);
                if (enabledAccessibilityComponents.contains(componentName.flattenToString())
                        || enabledAccessibilityComponents.contains(componentName.flattenToShortString())) {
                    signals.enabledAccessibilityServices++;
                }
            } else if (PERMISSION_BIND_VPN.equals(service.permission)) {
                signals.vpnServices++;
            } else if (PERMISSION_BIND_NOTIFICATION_LISTENER.equals(service.permission)) {
                signals.notificationListenerServices++;
            }
        }
        return signals;
    }

    private AdminSignals inspectDeviceAdmin(PackageInfo packageInfo, Set<String> activeAdminPackages) {
        AdminSignals signals = new AdminSignals();
        signals.activeAdmin = activeAdminPackages.contains(packageInfo.packageName);
        if (packageInfo.receivers == null) {
            return signals;
        }
        for (ActivityInfo receiver : packageInfo.receivers) {
            if (receiver != null && PERMISSION_BIND_DEVICE_ADMIN.equals(receiver.permission)) {
                signals.declaredAdmins++;
            }
        }
        return signals;
    }

    private boolean isOverlayAllowed(ApplicationInfo appInfo) {
        AppOpsManager appOpsManager = (AppOpsManager) context.getSystemService(Context.APP_OPS_SERVICE);
        if (appOpsManager == null) {
            return false;
        }
        try {
            int mode;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                mode = appOpsManager.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, appInfo.uid, appInfo.packageName);
            } else {
                mode = appOpsManager.checkOpNoThrow(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, appInfo.uid, appInfo.packageName);
            }
            return mode == AppOpsManager.MODE_ALLOWED || mode == AppOpsManager.MODE_FOREGROUND;
        } catch (Exception ignored) {
            return false;
        }
    }

    private Set<String> queryLauncherPackages(PackageManager packageManager) {
        Set<String> packages = new HashSet<>();
        Intent launcherIntent = new Intent(Intent.ACTION_MAIN);
        launcherIntent.addCategory(Intent.CATEGORY_LAUNCHER);
        for (ResolveInfo resolveInfo : queryIntentActivities(packageManager, launcherIntent, 0)) {
            if (resolveInfo.activityInfo != null) {
                packages.add(resolveInfo.activityInfo.packageName);
            }
        }
        Intent leanbackIntent = new Intent(Intent.ACTION_MAIN);
        leanbackIntent.addCategory(Intent.CATEGORY_LEANBACK_LAUNCHER);
        for (ResolveInfo resolveInfo : queryIntentActivities(packageManager, leanbackIntent, 0)) {
            if (resolveInfo.activityInfo != null) {
                packages.add(resolveInfo.activityInfo.packageName);
            }
        }
        return packages;
    }

    private Set<String> queryBootReceiverPackages(PackageManager packageManager) {
        Set<String> packages = new HashSet<>();
        List<String> actions = Arrays.asList(
                Intent.ACTION_BOOT_COMPLETED,
                Intent.ACTION_LOCKED_BOOT_COMPLETED,
                "android.intent.action.QUICKBOOT_POWERON",
                "com.htc.intent.action.QUICKBOOT_POWERON"
        );
        for (String action : actions) {
            Intent intent = new Intent(action);
            for (ResolveInfo resolveInfo : queryBroadcastReceivers(packageManager, intent, 0)) {
                if (resolveInfo.activityInfo != null) {
                    packages.add(resolveInfo.activityInfo.packageName);
                }
            }
        }
        return packages;
    }

    private Set<String> readEnabledAccessibilityComponents() {
        Set<String> enabledComponents = new HashSet<>();
        String enabled = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
        if (TextUtils.isEmpty(enabled)) {
            return enabledComponents;
        }
        TextUtils.SimpleStringSplitter splitter = new TextUtils.SimpleStringSplitter(':');
        splitter.setString(enabled);
        while (splitter.hasNext()) {
            String component = splitter.next();
            if (!TextUtils.isEmpty(component)) {
                enabledComponents.add(component);
            }
        }
        return enabledComponents;
    }

    private Set<String> readActiveAdminPackages() {
        Set<String> activePackages = new HashSet<>();
        DevicePolicyManager devicePolicyManager = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        if (devicePolicyManager == null) {
            return activePackages;
        }
        try {
            List<ComponentName> activeAdmins = devicePolicyManager.getActiveAdmins();
            if (activeAdmins == null) {
                return activePackages;
            }
            for (ComponentName componentName : activeAdmins) {
                activePackages.add(componentName.getPackageName());
            }
        } catch (SecurityException ignored) {
            // Some enterprise builds restrict this to device/profile owners.
        }
        return activePackages;
    }

    private boolean hasActiveVpn() {
        ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager == null) {
            return false;
        }
        try {
            for (Network network : connectivityManager.getAllNetworks()) {
                NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(network);
                if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    return true;
                }
            }
        } catch (SecurityException ignored) {
            return false;
        }
        return false;
    }

    private String readProxySummary() {
        String host = System.getProperty("http.proxyHost");
        String port = System.getProperty("http.proxyPort");
        if (!TextUtils.isEmpty(host)) {
            return "HTTP proxy " + host + (TextUtils.isEmpty(port) ? "" : ":" + port);
        }
        try {
            String globalProxy = Settings.Global.getString(context.getContentResolver(), "http_proxy");
            if (!TextUtils.isEmpty(globalProxy) && !":0".equals(globalProxy)) {
                return "HTTP proxy " + globalProxy;
            }
        } catch (Exception ignored) {
            return "Proxy status unavailable.";
        }
        return "No system HTTP proxy detected.";
    }

    private InstallSource readInstallSource(PackageManager packageManager, String packageName, boolean systemApp) {
        if (systemApp) {
            return new InstallSource(null, "System image or OEM update", true, false);
        }
        String installerPackage = null;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                InstallSourceInfo installSourceInfo = packageManager.getInstallSourceInfo(packageName);
                installerPackage = installSourceInfo.getInstallingPackageName();
                if (TextUtils.isEmpty(installerPackage) && installSourceInfo.getInitiatingPackageName() != null) {
                    installerPackage = installSourceInfo.getInitiatingPackageName();
                }
            } else {
                installerPackage = packageManager.getInstallerPackageName(packageName);
            }
        } catch (Exception ignored) {
            installerPackage = null;
        }
        boolean unknown = TextUtils.isEmpty(installerPackage);
        boolean trusted = !unknown && TRUSTED_INSTALLERS.contains(installerPackage);
        String display;
        if (unknown) {
            display = "Installer: unknown";
        } else {
            display = "Installer: " + readPackageLabel(packageManager, installerPackage) + " (" + installerPackage + ")";
        }
        return new InstallSource(installerPackage, display, trusted, unknown);
    }

    private SignatureState readSignatureState(PackageInfo packageInfo) {
        List<Signature> signatures = new ArrayList<>();
        boolean multipleSigners = false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            SigningInfo signingInfo = packageInfo.signingInfo;
            if (signingInfo != null) {
                Signature[] packageSignatures;
                if (signingInfo.hasMultipleSigners()) {
                    multipleSigners = true;
                    packageSignatures = signingInfo.getApkContentsSigners();
                } else {
                    packageSignatures = signingInfo.getSigningCertificateHistory();
                }
                if (packageSignatures != null) {
                    signatures.addAll(Arrays.asList(packageSignatures));
                }
            }
        } else if (packageInfo.signatures != null) {
            signatures.addAll(Arrays.asList(packageInfo.signatures));
            multipleSigners = signatures.size() > 1;
        }

        if (signatures.isEmpty()) {
            return new SignatureState(false, false, false, "Unavailable", "Unavailable");
        }

        String primarySha256 = sha256(signatures.get(0).toByteArray());
        boolean debug = false;
        for (Signature signature : signatures) {
            if (isDebugCertificate(signature)) {
                debug = true;
                break;
            }
        }
        String summary = signatures.size() + " signer" + (signatures.size() == 1 ? "" : "s") + "; SHA-256 " + primarySha256;
        return new SignatureState(true, debug, multipleSigners, summary, primarySha256);
    }

    private boolean isDebugCertificate(Signature signature) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(signature.toByteArray()));
            String subject = certificate.getSubjectX500Principal().getName();
            return subject != null && subject.toLowerCase(Locale.US).contains("android debug");
        } catch (Exception ignored) {
            return false;
        }
    }

    private String sha256(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(bytes);
            StringBuilder builder = new StringBuilder(hashed.length * 3);
            for (int i = 0; i < hashed.length; i++) {
                if (i > 0) {
                    builder.append(':');
                }
                builder.append(String.format(Locale.US, "%02X", hashed[i]));
            }
            return builder.toString();
        } catch (Exception ignored) {
            return "Unavailable";
        }
    }

    private String readLabel(PackageManager packageManager, ApplicationInfo appInfo, String fallback) {
        try {
            CharSequence label = packageManager.getApplicationLabel(appInfo);
            if (!TextUtils.isEmpty(label)) {
                return label.toString();
            }
        } catch (Exception ignored) {
            // Fall through to package name.
        }
        return fallback;
    }

    private Drawable readIcon(PackageManager packageManager, ApplicationInfo appInfo) {
        try {
            return packageManager.getApplicationIcon(appInfo);
        } catch (Exception ignored) {
            return context.getApplicationInfo().loadIcon(packageManager);
        }
    }

    private String readPackageLabel(PackageManager packageManager, String packageName) {
        try {
            ApplicationInfo info;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                info = packageManager.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0));
            } else {
                info = packageManager.getApplicationInfo(packageName, 0);
            }
            return readLabel(packageManager, info, packageName);
        } catch (PackageManager.NameNotFoundException ignored) {
            return packageName;
        }
    }

    private boolean isSystemApp(ApplicationInfo appInfo) {
        return (appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                || (appInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
    }

    private long packageInfoFlags() {
        long flags = PackageManager.GET_PERMISSIONS
                | PackageManager.GET_SERVICES
                | PackageManager.GET_RECEIVERS
                | PackageManager.GET_ACTIVITIES
                | PackageManager.GET_META_DATA
                | PackageManager.MATCH_DISABLED_COMPONENTS;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            flags |= PackageManager.GET_SIGNING_CERTIFICATES;
        } else {
            flags |= PackageManager.GET_SIGNATURES;
        }
        return flags;
    }

    private List<PackageInfo> getInstalledPackages(PackageManager packageManager, long flags) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags));
        }
        return packageManager.getInstalledPackages((int) flags);
    }

    private List<ResolveInfo> queryIntentActivities(PackageManager packageManager, Intent intent, long flags) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return packageManager.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(flags));
        }
        return packageManager.queryIntentActivities(intent, (int) flags);
    }

    private List<ResolveInfo> queryBroadcastReceivers(PackageManager packageManager, Intent intent, long flags) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return packageManager.queryBroadcastReceivers(intent, PackageManager.ResolveInfoFlags.of(flags));
        }
        return packageManager.queryBroadcastReceivers(intent, (int) flags);
    }

    private boolean hasAny(Set<String> requestedPermissions, Set<String> targets) {
        for (String target : targets) {
            if (requestedPermissions.contains(target)) {
                return true;
            }
        }
        return false;
    }

    private int add(List<RiskFinding> findings, RiskFinding.Severity severity, String title, String detail, int weight) {
        findings.add(new RiskFinding(severity, title, detail, weight));
        return weight;
    }

    private static Set<String> setOf(String... values) {
        return new HashSet<>(Arrays.asList(values));
    }

    private static final class InstallSource {
        final String installerPackage;
        final String displayText;
        final boolean trusted;
        final boolean unknown;

        InstallSource(String installerPackage, String displayText, boolean trusted, boolean unknown) {
            this.installerPackage = installerPackage;
            this.displayText = displayText;
            this.trusted = trusted;
            this.unknown = unknown;
        }
    }

    private static final class SignatureState {
        final boolean available;
        final boolean debugCertificate;
        final boolean multipleSigners;
        final String summary;
        final String primarySha256;

        SignatureState(boolean available, boolean debugCertificate, boolean multipleSigners, String summary, String primarySha256) {
            this.available = available;
            this.debugCertificate = debugCertificate;
            this.multipleSigners = multipleSigners;
            this.summary = summary;
            this.primarySha256 = primarySha256;
        }
    }

    private static final class ServiceSignals {
        int declaredAccessibilityServices;
        int enabledAccessibilityServices;
        int vpnServices;
        int notificationListenerServices;
    }

    private static final class AdminSignals {
        int declaredAdmins;
        boolean activeAdmin;
    }
}
