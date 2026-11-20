import React, { useMemo } from 'react';
import type { ManagedItem } from '../types';

interface SummaryGridProps {
  items: ManagedItem[];
  tasksCount: number;
  scannedAt?: string;
}

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
    for (const it of items) {
      crit += it.crit_count || 0;
      high += it.high_count || 0;
      if (it.eol && (it.eol.status === 'expired' || it.eol.status === 'expiring_soon')) {
        eol++;
      }
      if (it.outdated) outdated++;
      if (it.skipped) skipped++;
      if (it.broken_linkage) broken++;
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
      <div className="bg-slate-800 border border-slate-700 border-l-4 border-l-red-500 rounded-xl px-5 py-4.5">
        <div className="text-xs uppercase tracking-wider text-slate-400">Security Vulnerabilities</div>
        <div className="text-[28px] font-extrabold my-1.5 text-red-300" id="stat-cves">
          {stats.crit} Critical / {stats.high} High
        </div>
        <div className="text-xs text-slate-400" id="stat-cves-sub">
          OSV.dev + Trivy CVE Scanner
        </div>
      </div>

      <div className="bg-slate-800 border border-slate-700 border-l-4 border-l-amber-500 rounded-xl px-5 py-4.5">
        <div className="text-xs uppercase tracking-wider text-slate-400">LTS / EoL Window</div>
        <div className="text-[28px] font-extrabold my-1.5 text-amber-300" id="stat-eol">
          {stats.eol} Expiring/EoL
        </div>
        <div className="text-xs text-slate-400">Tracked via endoflife.date + Vendor Windows</div>
      </div>

      <div className="bg-slate-800 border border-slate-700 border-l-4 border-l-amber-500 rounded-xl px-5 py-4.5">
        <div className="text-xs uppercase tracking-wider text-slate-400">Outdated Packages</div>
        <div className="text-[28px] font-extrabold my-1.5 text-slate-50" id="stat-outdated">
          {stats.outdated} Updates
        </div>
        <div className="text-xs text-slate-400" id="stat-outdated-sub">
          {stats.skipped} Skipped · {stats.broken} Broken Linkage
        </div>
      </div>

      <div className="bg-slate-800 border border-slate-700 border-l-4 border-l-emerald-500 rounded-xl px-5 py-4.5">
        <div className="text-xs uppercase tracking-wider text-slate-400">Task Logs &amp; Snapshots</div>
        <div className="text-[28px] font-extrabold my-1.5 text-emerald-300" id="stat-tasks">
          {tasksCount} Runs
        </div>
        <div className="text-xs text-slate-400" id="stat-last-scan">
          {lastScanLabel}
        </div>
      </div>
    </div>
  );
};
