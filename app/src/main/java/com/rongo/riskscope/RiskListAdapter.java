package com.rongo.riskscope;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.core.content.ContextCompat;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class RiskListAdapter extends BaseAdapter {
    private final LayoutInflater inflater;
    private final Context context;
    private final List<AppRiskReport> reports = new ArrayList<>();

    public RiskListAdapter(Context context) {
        this.context = context;
        this.inflater = LayoutInflater.from(context);
    }

    public void submit(List<AppRiskReport> nextReports) {
        reports.clear();
        reports.addAll(nextReports);
        notifyDataSetChanged();
    }

    @Override
    public int getCount() {
        return reports.size();
    }

    @Override
    public AppRiskReport getItem(int position) {
        return reports.get(position);
    }

    @Override
    public long getItemId(int position) {
        return reports.get(position).getPackageName().hashCode();
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View row = convertView;
        ViewHolder holder;
        if (row == null) {
            row = inflater.inflate(R.layout.item_app_risk, parent, false);
            holder = new ViewHolder(row);
            row.setTag(holder);
        } else {
            holder = (ViewHolder) row.getTag();
        }

        AppRiskReport report = getItem(position);
        holder.icon.setImageDrawable(report.getIcon());
        holder.icon.setContentDescription(report.getLabel());
        holder.name.setText(report.getLabel());
        holder.packageName.setText(report.getPackageName());
        holder.findingSummary.setText(report.getFindingSummary());
        holder.sourceSummary.setText(report.getSourceSummary());
        holder.riskBadge.setText(String.format(Locale.US, "%d %s", report.getRiskScore(), report.getRiskLevelLabel()));

        int riskColor = colorForScore(report.getRiskScore());
        holder.riskBadge.setBackground(rounded(riskColor));
        holder.progress.setProgress(report.getRiskScore());
        Drawable progressDrawable = holder.progress.getProgressDrawable();
        if (progressDrawable != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            progressDrawable.mutate().setTint(riskColor);
        }
        return row;
    }

    private int colorForScore(int score) {
        if (score >= 70) {
            return ContextCompat.getColor(context, R.color.risk_high);
        }
        if (score >= 40) {
            return ContextCompat.getColor(context, R.color.risk_medium);
        }
        if (score > 0) {
            return ContextCompat.getColor(context, R.color.risk_low);
        }
        return ContextCompat.getColor(context, R.color.risk_neutral);
    }

    private Drawable rounded(int color) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(context.getResources().getDisplayMetrics().density * 8f);
        return drawable;
    }

    private static final class ViewHolder {
        final ImageView icon;
        final TextView name;
        final TextView packageName;
        final TextView riskBadge;
        final ProgressBar progress;
        final TextView findingSummary;
        final TextView sourceSummary;

        ViewHolder(View row) {
            icon = row.findViewById(R.id.appIcon);
            name = row.findViewById(R.id.appName);
            packageName = row.findViewById(R.id.packageName);
            riskBadge = row.findViewById(R.id.riskBadge);
            progress = row.findViewById(R.id.riskProgress);
            findingSummary = row.findViewById(R.id.findingSummary);
            sourceSummary = row.findViewById(R.id.sourceSummary);
        }
    }
}
