package com.rongo.riskscope;

public final class RiskFinding {
    public enum Severity {
        LOW,
        MEDIUM,
        HIGH
    }

    private final Severity severity;
    private final String title;
    private final String detail;
    private final int weight;

    public RiskFinding(Severity severity, String title, String detail, int weight) {
        this.severity = severity;
        this.title = title;
        this.detail = detail;
        this.weight = weight;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getTitle() {
        return title;
    }

    public String getDetail() {
        return detail;
    }

    public int getWeight() {
        return weight;
    }
}
