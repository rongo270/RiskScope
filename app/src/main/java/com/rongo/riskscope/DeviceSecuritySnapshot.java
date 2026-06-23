package com.rongo.riskscope;

import java.util.List;

public final class DeviceSecuritySnapshot {
    private final int overallScore;
    private final int scannedAppCount;
    private final int highRiskCount;
    private final int mediumRiskCount;
    private final int lowRiskCount;
    private final boolean activeVpn;
    private final String proxySummary;
    private final long scanTimeMillis;

    public DeviceSecuritySnapshot(
            int overallScore,
            int scannedAppCount,
            int highRiskCount,
            int mediumRiskCount,
            int lowRiskCount,
            boolean activeVpn,
            String proxySummary,
            long scanTimeMillis
    ) {
        this.overallScore = Math.max(0, Math.min(100, overallScore));
        this.scannedAppCount = scannedAppCount;
        this.highRiskCount = highRiskCount;
        this.mediumRiskCount = mediumRiskCount;
        this.lowRiskCount = lowRiskCount;
        this.activeVpn = activeVpn;
        this.proxySummary = proxySummary;
        this.scanTimeMillis = scanTimeMillis;
    }

    public static DeviceSecuritySnapshot fromReports(
            List<AppRiskReport> reports,
            boolean activeVpn,
            String proxySummary,
            long scanTimeMillis
    ) {
        int high = 0;
        int medium = 0;
        int low = 0;
        int max = 0;
        int topFiveTotal = 0;
        int topFiveCount = Math.min(5, reports.size());
        for (int i = 0; i < reports.size(); i++) {
            int score = reports.get(i).getRiskScore();
            max = Math.max(max, score);
            if (i < topFiveCount) {
                topFiveTotal += score;
            }
            if (score >= 70) {
                high++;
            } else if (score >= 40) {
                medium++;
            } else if (score > 0) {
                low++;
            }
        }
        int topAverage = topFiveCount == 0 ? 0 : Math.round(topFiveTotal / (float) topFiveCount);
        int posturePenalty = high * 10 + medium * 4;
        if (activeVpn) {
            posturePenalty += 3;
        }
        if (proxySummary != null && proxySummary.startsWith("HTTP proxy")) {
            posturePenalty += 5;
        }
        int overall = Math.min(100, Math.max(max, Math.max(topAverage, posturePenalty)));
        return new DeviceSecuritySnapshot(overall, reports.size(), high, medium, low, activeVpn, proxySummary, scanTimeMillis);
    }

    public int getOverallScore() {
        return overallScore;
    }

    public int getScannedAppCount() {
        return scannedAppCount;
    }

    public int getHighRiskCount() {
        return highRiskCount;
    }

    public int getMediumRiskCount() {
        return mediumRiskCount;
    }

    public int getLowRiskCount() {
        return lowRiskCount;
    }

    public boolean hasActiveVpn() {
        return activeVpn;
    }

    public String getProxySummary() {
        return proxySummary;
    }

    public long getScanTimeMillis() {
        return scanTimeMillis;
    }

    public String getOverallLabel() {
        if (overallScore >= 70) {
            return "High attention";
        }
        if (overallScore >= 40) {
            return "Moderate attention";
        }
        if (overallScore > 0) {
            return "Low attention";
        }
        return "Clean baseline";
    }

    public String getPostureSummary() {
        return scannedAppCount + " apps scanned. "
                + highRiskCount + " high, "
                + mediumRiskCount + " medium, "
                + lowRiskCount + " low. VPN active: "
                + (activeVpn ? "yes" : "no") + ". "
                + proxySummary;
    }
}
