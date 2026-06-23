package com.rongo.riskscope;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class RiskScanResult {
    private final DeviceSecuritySnapshot snapshot;
    private final List<AppRiskReport> appReports;

    public RiskScanResult(DeviceSecuritySnapshot snapshot, List<AppRiskReport> appReports) {
        this.snapshot = snapshot;
        this.appReports = Collections.unmodifiableList(new ArrayList<>(appReports));
    }

    public DeviceSecuritySnapshot getSnapshot() {
        return snapshot;
    }

    public List<AppRiskReport> getAppReports() {
        return appReports;
    }
}
