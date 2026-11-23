import type React from 'react';
import { cn } from '../lib/cn';
import type { TabType } from '../types';

const TABS: { id: TabType; label: string; badgeId: string }[] = [
  { id: 'docker', label: 'Docker Services (`services/*`)', badgeId: 'badge-docker' },
  { id: 'brew', label: 'System Packages (`brew` / `apt`)', badgeId: 'badge-brew' },
  { id: 'daemons', label: 'Host Daemons & macOS', badgeId: 'badge-daemons' },
  { id: 'logs', label: 'Task Logs & Audit Console', badgeId: 'badge-logs' },
];

interface DashboardTabsProps {
  currentTab: TabType;
  counts: Record<TabType, number>;
  onSelectTab: (tab: TabType) => void;
}

/**
 * Accessible tab strip for switching between Docker, System Packages, Daemons, and Task Logs views.
 */
export const DashboardTabs: React.FC<DashboardTabsProps> = ({
  currentTab,
  counts,
  onSelectTab,
}) => {
  return (
    <div
      role="tablist"
      aria-label="Security Hub Views"
      className="flex gap-1 border-b border-slate-700 mb-5 flex-wrap"
    >
      {TABS.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          aria-selected={currentTab === tab.id}
          id={`tab-btn-${tab.id}`}
          className={cn(
            'bg-transparent border-0 border-b-2 px-4.5 py-2.5 cursor-pointer font-semibold text-sm flex items-center gap-2 transition-colors',
            currentTab === tab.id
              ? 'text-sky-400 border-sky-400'
              : 'text-slate-400 border-transparent hover:text-slate-200'
          )}
          onClick={() => onSelectTab(tab.id)}
        >
          {tab.label}{' '}
          <span
            className="bg-slate-700 text-slate-50 text-[11px] px-1.75 py-0.25 rounded-full"
            id={tab.badgeId}
          >
            {counts[tab.id]}
          </span>
        </button>
      ))}
    </div>
  );
};
