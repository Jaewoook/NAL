import type React from 'react';
import { useMemo } from 'react';
import { cn } from '../lib/cn';
import type { ManagedItem } from '../types';

interface SummaryGridProps {
  items: ManagedItem[];
  tasksCount: number;
  scannedAt?: string;
}

interface StatCardProps {
  accentBorderClass: string;
  label: string;
  value: string;
  valueClass: string;
  valueId: string;
  subtitle: string;
  subtitleId?: string;
}

const StatCard: React.FC<StatCardProps> = ({
  accentBorderClass,
  label,
  value,
  valueClass,
  valueId,
  subtitle,
  subtitleId,
}) => (
  <div
    className={cn(
      'bg-slate-800 border border-slate-700 border-l-4 rounded-xl px-5 py-4.5',
      accentBorderClass
    )}
  >
    <div className="text-xs uppercase tracking-wider text-slate-400">{label}</div>
    <div className={cn('text-[28px] font-extrabold my-1.5', valueClass)} id={valueId}>
      {value}
    </div>
    <div className="text-xs text-slate-400" id={subtitleId}>
      {subtitle}
    </div>
  </div>
);

/**
 * Displays aggregate CVE, EoL, outdated package, and task run counts for the selected node filter.
 */
export const SummaryGrid: React.FC<SummaryGridProps> = ({ items, tasksCount, scannedAt }) => {
  const stats = useMemo(() => {
    let crit = 0;
    let high = 0;
    let eol = 0;
    let outdated = 0;
    let skipped = 0;
    let broken = 0;
    for (const item of items) {
      crit += item.crit_count || 0;
      high += item.high_count || 0;
      if (item.eol && (item.eol.status === 'expired' || item.eol.status === 'expiring_soon')) {
        eol++;
      }
      if (item.outdated) outdated++;
      if (item.skipped) skipped++;
      if (item.broken_linkage) broken++;
    }
    return { crit, high, eol, outdated, skipped, broken };
  }, [items]);

  const hasScanTime = Boolean(scannedAt && !String(scannedAt).startsWith('0001-'));
  const lastScanLabel =
    hasScanTime && scannedAt
      ? `Last scan: ${new Date(scannedAt).toLocaleString()}`
      : 'Last scan: Not yet run';

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      <StatCard
        accentBorderClass="border-l-red-500"
        label="Security Vulnerabilities"
        value={`${stats.crit} Critical / ${stats.high} High`}
        valueClass="text-red-300"
        valueId="stat-cves"
        subtitle="OSV.dev + Trivy CVE Scanner"
        subtitleId="stat-cves-sub"
      />
      <StatCard
        accentBorderClass="border-l-amber-500"
        label="LTS / EoL Window"
        value={`${stats.eol} Expiring/EoL`}
        valueClass="text-amber-300"
        valueId="stat-eol"
        subtitle="Tracked via endoflife.date + Vendor Windows"
      />
      <StatCard
        accentBorderClass="border-l-amber-500"
        label="Outdated Packages"
        value={`${stats.outdated} Updates`}
        valueClass="text-slate-50"
        valueId="stat-outdated"
        subtitle={`${stats.skipped} Skipped · ${stats.broken} Broken Linkage`}
        subtitleId="stat-outdated-sub"
      />
      <StatCard
        accentBorderClass="border-l-emerald-500"
        label="Task Logs & Snapshots"
        value={`${tasksCount} Runs`}
        valueClass="text-emerald-300"
        valueId="stat-tasks"
        subtitle={lastScanLabel}
        subtitleId="stat-last-scan"
      />
    </div>
  );
};
