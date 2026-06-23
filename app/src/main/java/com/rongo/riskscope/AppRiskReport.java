package com.rongo.riskscope;

import android.graphics.drawable.Drawable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class AppRiskReport {
    private final String label;
    private final String packageName;
    private final String versionName;
    private final String installSource;
    private final String certificateSummary;
    private final String certificateSha256;
    private final long firstInstallTime;
    private final long lastUpdateTime;
    private final int riskScore;
    private final boolean systemApp;
    private final boolean enabled;
    private final boolean hasLauncher;
    private final Drawable icon;
    private final List<RiskFinding> findings;
    private final List<String> dangerousPermissions;
    private final List<String> grantedDangerousPermissions;

    public AppRiskReport(
            String label,
            String packageName,
            String versionName,
            String installSource,
            String certificateSummary,
            String certificateSha256,
            long firstInstallTime,
            long lastUpdateTime,
            int riskScore,
            boolean systemApp,
            boolean enabled,
            boolean hasLauncher,
            Drawable icon,
            List<RiskFinding> findings,
            List<String> dangerousPermissions,
            List<String> grantedDangerousPermissions
    ) {
        this.label = label;
        this.packageName = packageName;
        this.versionName = versionName;
        this.installSource = installSource;
        this.certificateSummary = certificateSummary;
        this.certificateSha256 = certificateSha256;
        this.firstInstallTime = firstInstallTime;
        this.lastUpdateTime = lastUpdateTime;
        this.riskScore = Math.max(0, Math.min(100, riskScore));
        this.systemApp = systemApp;
        this.enabled = enabled;
        this.hasLauncher = hasLauncher;
        this.icon = icon;
        this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
        this.dangerousPermissions = Collections.unmodifiableList(new ArrayList<>(dangerousPermissions));
        this.grantedDangerousPermissions = Collections.unmodifiableList(new ArrayList<>(grantedDangerousPermissions));
    }

    public String getLabel() {
        return label;
    }

    public String getPackageName() {
        return packageName;
    }

    public String getVersionName() {
        return versionName;
    }

    public String getInstallSource() {
        return installSource;
    }

    public String getCertificateSummary() {
        return certificateSummary;
    }

    public String getCertificateSha256() {
        return certificateSha256;
    }

    public long getFirstInstallTime() {
        return firstInstallTime;
    }

    public long getLastUpdateTime() {
        return lastUpdateTime;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public boolean isSystemApp() {
        return systemApp;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean hasLauncher() {
        return hasLauncher;
    }

    public Drawable getIcon() {
        return icon;
    }

    public List<RiskFinding> getFindings() {
        return findings;
    }

    public List<String> getDangerousPermissions() {
        return dangerousPermissions;
    }

    public List<String> getGrantedDangerousPermissions() {
        return grantedDangerousPermissions;
    }

    public String getRiskLevelLabel() {
        if (riskScore >= 70) {
            return "High";
        }
        if (riskScore >= 40) {
            return "Medium";
        }
        if (riskScore > 0) {
            return "Low";
        }
        return "Clear";
    }

    public String getFindingSummary() {
        if (findings.isEmpty()) {
            return "No suspicious signals found in visible metadata.";
        }
        StringBuilder summary = new StringBuilder();
        int count = Math.min(2, findings.size());
        for (int i = 0; i < count; i++) {
            if (i > 0) {
                summary.append(" | ");
            }
            summary.append(findings.get(i).getTitle());
        }
        if (findings.size() > count) {
            summary.append(" | +").append(findings.size() - count).append(" more");
        }
        return summary.toString();
    }

    public String getSourceSummary() {
        String type = systemApp ? "System" : "User";
        String launch = hasLauncher ? "launcher" : "no launcher";
        return type + " app | " + launch + " | " + installSource;
    }
}
