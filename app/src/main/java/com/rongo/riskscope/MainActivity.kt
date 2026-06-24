package com.rongo.riskscope;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.View;
import android.widget.ListView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.text.DateFormat;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends AppCompatActivity {
    private final ExecutorService scannerExecutor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private TextView overallScore;
    private TextView overallLabel;
    private TextView devicePosture;
    private TextView resultMeta;
    private TextView emptyState;
    private MaterialButton scanButton;
    private RiskListAdapter adapter;
    private boolean destroyed;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        MaterialToolbar toolbar = findViewById(R.id.topAppBar);
        setSupportActionBar(toolbar);

        overallScore = findViewById(R.id.overallScore);
        overallLabel = findViewById(R.id.overallLabel);
        devicePosture = findViewById(R.id.devicePosture);
        resultMeta = findViewById(R.id.resultMeta);
        emptyState = findViewById(R.id.emptyState);
        scanButton = findViewById(R.id.scanButton);
        ListView appList = findViewById(R.id.appList);

        adapter = new RiskListAdapter(this);
        appList.setAdapter(adapter);
        appList.setOnItemClickListener((parent, view, position, id) -> showDetails(adapter.getItem(position)));
        scanButton.setOnClickListener(view -> runScan());

        runScan();
    }

    @Override
    protected void onDestroy() {
        destroyed = true;
        scannerExecutor.shutdownNow();
        super.onDestroy();
    }

    private void runScan() {
        scanButton.setEnabled(false);
        scanButton.setText(R.string.scanning);
        emptyState.setVisibility(View.VISIBLE);
        emptyState.setText(R.string.scanning);
        resultMeta.setText("Scanning installed apps with local Android APIs.");

        scannerExecutor.execute(() -> {
            RiskScanResult result = null;
            Exception error = null;
            try {
                result = new RiskAnalyzer(getApplicationContext()).scan();
            } catch (Exception exception) {
                error = exception;
            }
            RiskScanResult finalResult = result;
            Exception finalError = error;
            mainHandler.post(() -> {
                if (destroyed) {
                    return;
                }
                scanButton.setEnabled(true);
                scanButton.setText(R.string.scan_now);
                if (finalError != null) {
                    showScanError(finalError);
                } else if (finalResult != null) {
                    renderResult(finalResult);
                }
            });
        });
    }

    private void renderResult(RiskScanResult result) {
        DeviceSecuritySnapshot snapshot = result.getSnapshot();
        adapter.submit(result.getAppReports());
        emptyState.setVisibility(result.getAppReports().isEmpty() ? View.VISIBLE : View.GONE);
        emptyState.setText("No apps were visible to scan.");

        overallScore.setText(String.valueOf(snapshot.getOverallScore()));
        overallLabel.setText(snapshot.getOverallLabel());
        overallLabel.setTextColor(colorForScore(snapshot.getOverallScore()));
        devicePosture.setText(snapshot.getPostureSummary());
        resultMeta.setText(String.format(
                Locale.US,
                "%d apps scanned in %d ms. Tap an app for evidence and settings.",
                snapshot.getScannedAppCount(),
                snapshot.getScanTimeMillis()
        ));
    }

    private void showScanError(Exception error) {
        emptyState.setVisibility(View.VISIBLE);
        emptyState.setText("Scan failed.");
        resultMeta.setText("Scan failed: " + error.getClass().getSimpleName());
        new MaterialAlertDialogBuilder(this)
                .setTitle("Scan failed")
                .setMessage(error.getMessage() == null ? error.toString() : error.getMessage())
                .setPositiveButton(R.string.close, null)
                .show();
    }

    private void showDetails(AppRiskReport report) {
        StringBuilder details = new StringBuilder();
        details.append("Package: ").append(report.getPackageName()).append('\n');
        details.append("Version: ").append(report.getVersionName()).append('\n');
        details.append("Risk score: ").append(report.getRiskScore()).append(" / 100 (").append(report.getRiskLevelLabel()).append(")\n");
        details.append("Type: ").append(report.isSystemApp() ? "System" : "User").append(" app\n");
        details.append("Enabled: ").append(report.isEnabled() ? "yes" : "no").append('\n');
        details.append("Launcher entry: ").append(report.hasLauncher() ? "yes" : "no").append("\n\n");

        details.append("Install source\n").append(report.getInstallSource()).append("\n\n");
        details.append("Certificate\n").append(report.getCertificateSummary()).append("\n\n");
        details.append("First installed: ").append(formatDate(report.getFirstInstallTime())).append('\n');
        details.append("Last updated: ").append(formatDate(report.getLastUpdateTime())).append("\n\n");

        details.append("Findings\n");
        if (report.getFindings().isEmpty()) {
            details.append("No suspicious signals found in visible metadata.\n");
        } else {
            for (RiskFinding finding : report.getFindings()) {
                details.append("- ")
                        .append(finding.getTitle())
                        .append(" (")
                        .append(finding.getSeverity().name().toLowerCase(Locale.US))
                        .append(", +")
                        .append(finding.getWeight())
                        .append("): ")
                        .append(finding.getDetail())
                        .append('\n');
            }
        }

        details.append("\nDangerous permissions requested\n")
                .append(formatList(report.getDangerousPermissions(), 18))
                .append("\n\nDangerous permissions granted\n")
                .append(formatList(report.getGrantedDangerousPermissions(), 18));

        new MaterialAlertDialogBuilder(this)
                .setTitle(report.getLabel())
                .setMessage(details.toString())
                .setPositiveButton(R.string.open_app_settings, (dialog, which) -> openAppSettings(report.getPackageName()))
                .setNegativeButton(R.string.close, null)
                .show();
    }

    private void openAppSettings(String packageName) {
        Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + packageName));
        try {
            startActivity(intent);
        } catch (ActivityNotFoundException ignored) {
            startActivity(new Intent(Settings.ACTION_SETTINGS));
        }
    }

    private String formatList(List<String> values, int maxItems) {
        if (values.isEmpty()) {
            return "None";
        }
        StringBuilder builder = new StringBuilder();
        int count = Math.min(values.size(), maxItems);
        for (int i = 0; i < count; i++) {
            if (i > 0) {
                builder.append('\n');
            }
            builder.append("- ").append(values.get(i));
        }
        if (values.size() > count) {
            builder.append('\n').append("+ ").append(values.size() - count).append(" more");
        }
        return builder.toString();
    }

    private String formatDate(long timestamp) {
        if (timestamp <= 0L) {
            return "Unknown";
        }
        return DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(timestamp);
    }

    private int colorForScore(int score) {
        if (score >= 70) {
            return ContextCompat.getColor(this, R.color.risk_high);
        }
        if (score >= 40) {
            return ContextCompat.getColor(this, R.color.risk_medium);
        }
        if (score > 0) {
            return ContextCompat.getColor(this, R.color.risk_low);
        }
        return ContextCompat.getColor(this, R.color.text_primary);
    }
}
