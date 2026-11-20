import React from 'react';
import { cn, getItemKey, isSafeHttpUrl } from '../api';
import type { ManagedItem } from '../types';

interface ItemsTableProps {
  items: ManagedItem[];
  hubNode: string;
  selectedVersions: Record<string, string>;
  onSelectVersion: (itemKey: string, version: string) => void;
  onOpenBrokenLinkage: (pkgName: string, details: string) => void;
  onOpenUpdateModal: (item: ManagedItem, targetVersion: string) => void;
  onSkipItem: (item: ManagedItem, targetVersion: string) => void;
  onUnskipItem: (item: ManagedItem) => void;
  onRollbackService: (nodeName: string, serviceName: string) => void;
}

/**
 * Renders the sortable managed packages/containers table for the active tab and node filter.
 */
export const ItemsTable: React.FC<ItemsTableProps> = ({
  items,
  hubNode,
  selectedVersions,
  onSelectVersion,
  onOpenBrokenLinkage,
  onOpenUpdateModal,
  onSkipItem,
  onUnskipItem,
  onRollbackService,
}) => {
  return (
    <div id="panel-items" className="bg-slate-800 border border-slate-700 rounded-xl overflow-x-auto">
      <table className="w-full border-collapse text-[13.5px]">
        <thead>
          <tr>
            <th className="text-left px-4 py-3 bg-[#141d2f] text-slate-400 font-semibold text-xs uppercase border-b border-slate-700">
              Service / Package
            </th>
            <th className="text-left px-4 py-3 bg-[#141d2f] text-slate-400 font-semibold text-xs uppercase border-b border-slate-700">
              Current Version
            </th>
            <th className="text-left px-4 py-3 bg-[#141d2f] text-slate-400 font-semibold text-xs uppercase border-b border-slate-700">
              CVEs &amp; Linkage
            </th>
            <th className="text-left px-4 py-3 bg-[#141d2f] text-slate-400 font-semibold text-xs uppercase border-b border-slate-700">
              LTS / EoL Status
            </th>
            <th className="text-left px-4 py-3 bg-[#141d2f] text-slate-400 font-semibold text-xs uppercase border-b border-slate-700">
              Target Version
            </th>
            <th className="text-left px-4 py-3 bg-[#141d2f] text-slate-400 font-semibold text-xs uppercase border-b border-slate-700">
              Actions
            </th>
          </tr>
        </thead>
        <tbody id="items-tbody">
          {items.length === 0 ? (
            <tr>
              <td colSpan={6} className="text-slate-400 text-[13px] text-center p-7">
                No components on this node/tab (uninstalled or stopped components are ignored automatically). Click{' '}
                <strong>↻ Scan Now</strong> to refresh.
              </td>
            </tr>
          ) : (
            items.map((item) => {
              const nodeName = item.node || hubNode || 'local';
              const itemKey = getItemKey(item, hubNode);
              const dotClass =
                item.crit_count > 0 || item.broken_linkage || item.eol?.status === 'expired'
                  ? 'red'
                  : item.high_count > 0 || item.eol?.status === 'expiring_soon' || item.outdated
                    ? 'amber'
                    : 'green';

              const tags =
                item.available_tags && item.available_tags.length > 0
                  ? item.available_tags
                  : [item.latest_version || item.current_version];
              const defaultVer = tags.includes(item.latest_version) ? item.latest_version : tags[0] || '';
              const selectedVer =
                selectedVersions[itemKey] && tags.includes(selectedVersions[itemKey])
                  ? selectedVersions[itemKey]
                  : defaultVer;

              const isUpdatable =
                item.target_type === 'docker' ||
                item.target_type === 'brew' ||
                item.target_type === 'apt' ||
                (item.target_type === 'daemon' && item.name === 'ollama');

              const subType =
                item.target_type === 'brew' || item.target_type === 'apt'
                  ? item.target_type
                  : item.image_ref || item.target_type;

              return (
                <tr
                  key={itemKey}
                  className="border-b border-slate-700 last:border-b-0 hover:bg-[#263449] transition-colors"
                >
                  <td className="px-4 py-3.5 align-middle">
                    <div className="flex flex-col gap-0.75">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="bg-slate-400/15 text-slate-300 border border-slate-600 text-[11px] px-1.75 py-0.25 rounded font-semibold inline-flex items-center">
                          {nodeName}
                        </span>
                        {item.critical_path && (
                          <span className="badge warn text-[10px] px-1.5 py-0.25">Critical Path</span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.75 font-bold text-[14.5px] text-slate-50 my-0.25">
                        <span className={cn('dot', dotClass)} />
                        <span>{item.name}</span>
                      </div>
                      <div className="text-xs text-slate-400 font-mono break-all">{subType}</div>
                    </div>
                  </td>

                  <td className="px-4 py-3.5 align-middle">
                    <div>{item.current_version}</div>
                    <div className="text-xs text-slate-400 font-mono break-all">
                      {(item.current_digest || '').slice(0, 19)}
                    </div>
                  </td>

                  <td className="px-4 py-3.5 align-middle">
                    {renderSecurityCell(item, onOpenBrokenLinkage)}
                  </td>

                  <td className="px-4 py-3.5 align-middle">{renderEolCell(item)}</td>

                  <td className="px-4 py-3.5 align-middle">
                    <select
                      className="ver-select"
                      aria-label={`Target version for ${item.name}`}
                      value={selectedVer}
                      onChange={(e) => onSelectVersion(itemKey, e.target.value)}
                    >
                      {tags.map((t, tagIdx) => (
                        <option key={`${t}-${tagIdx}`} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>
                  </td>

                  <td className="px-4 py-3.5 align-middle">
                    <div className="flex gap-1.5 items-center flex-wrap">
                      {isUpdatable && (
                        <>
                          <button
                            type="button"
                            className={cn(
                              'btn',
                              item.crit_count > 0 || item.broken_linkage ? 'btn-danger' : 'btn-primary'
                            )}
                            onClick={() => onOpenUpdateModal(item, selectedVer)}
                          >
                            {item.broken_linkage ? 'Upgrade & Fix' : 'Update'}
                          </button>

                          {item.skipped ? (
                            <>
                              <span className="badge skip">Skipped {item.skipped_version}</span>
                              <button
                                type="button"
                                className="btn btn-ghost"
                                onClick={() => onUnskipItem(item)}
                              >
                                Unskip
                              </button>
                            </>
                          ) : (
                            item.outdated && (
                              <button
                                type="button"
                                className="btn btn-ghost"
                                onClick={() => onSkipItem(item, selectedVer)}
                              >
                                Skip
                              </button>
                            )
                          )}

                          {item.has_rollback && (
                            <button
                              type="button"
                              className="btn btn-ghost"
                              onClick={() => onRollbackService(nodeName, item.name)}
                            >
                              Rollback ({item.rollback_version})
                            </button>
                          )}
                        </>
                      )}

                      {item.release_notes_url && isSafeHttpUrl(item.release_notes_url) && (
                        <a
                          className="btn btn-ghost no-underline"
                          href={item.release_notes_url}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Notes ↗
                        </a>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
};

function renderSecurityCell(
  item: ManagedItem,
  onOpenBrokenLinkage: (pkgName: string, details: string) => void
): React.ReactNode {
  const detailsText = item.linkage_details || 'Missing shared library dependency';
  const linkageBtnClass =
    'badge crit cursor-pointer border-red-500/45 hover:bg-red-500/28 hover:border-red-500 hover:text-white hover:-translate-y-px transition-all';

  if (item.broken_linkage && (item.crit_count > 0 || item.high_count > 0)) {
    return (
      <div className="flex flex-col gap-1 items-start">
        <button
          type="button"
          className={linkageBtnClass}
          onClick={() => onOpenBrokenLinkage(item.name, detailsText)}
        >
          ⚠ Broken Linkage (Details)
        </button>
        <span className="badge crit">
          ● {item.crit_count} Crit / {item.high_count} High
        </span>
      </div>
    );
  }
  if (item.broken_linkage) {
    return (
      <button
        type="button"
        className={linkageBtnClass}
        title="Click to view broken linkage details"
        onClick={() => onOpenBrokenLinkage(item.name, detailsText)}
      >
        ⚠ Broken Linkage (Details)
      </button>
    );
  }
  if (item.crit_count > 0 || item.high_count > 0) {
    const firstId = item.vulnerabilities?.[0]?.id || 'CVE';
    return (
      <span className="badge crit">
        ● {item.crit_count} Crit / {item.high_count} High ({firstId})
      </span>
    );
  }
  return <span className="badge ok">✓ 0 CVEs</span>;
}

function renderEolCell(item: ManagedItem): React.ReactNode {
  if (!item.eol) {
    return <span className="badge ok">Supported</span>;
  }
  if (item.eol.status === 'expired') {
    const tooltipText =
      item.eol.message || (item.eol.eol_date ? `End of Life reached on ${item.eol.eol_date}` : 'End of Life reached');
    return (
      <div className="tooltip-wrapper">
        <span className="badge crit">✖ EoL Expired</span>
        <div className="tooltip-box">{tooltipText}</div>
      </div>
    );
  }
  if (item.eol.status === 'expiring_soon') {
    const daysRemaining = item.eol.days_remaining ?? 0;
    const tooltipText =
      item.eol.message ||
      `End of Life scheduled in ${daysRemaining}d (${item.eol.eol_date || 'soon'})`;
    return (
      <div className="tooltip-wrapper">
        <span className="badge warn">⚠ EoL in {daysRemaining}d</span>
        <div className="tooltip-box">{tooltipText}</div>
      </div>
    );
  }
  if (item.eol.status === 'unknown') {
    const tooltipText = item.eol.message || 'Lifecycle track not mapped';
    return (
      <div className="tooltip-wrapper">
        <span className="badge skip">Not Tracked</span>
        <div className="tooltip-box">{tooltipText}</div>
      </div>
    );
  }
  if (item.eol.eol_date) {
    return (
      <div className="tooltip-wrapper">
        <span className="badge ok">Supported</span>
        <div className="tooltip-box">Supported until {item.eol.eol_date}</div>
      </div>
    );
  }
  return <span className="badge ok">Supported</span>;
}
