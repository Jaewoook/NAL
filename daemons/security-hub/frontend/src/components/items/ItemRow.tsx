import type React from 'react';
import { cn } from '../../lib/cn';
import { getItemKey, isSafeHttpUrl, resolveTargetVersion } from '../../lib/domain';
import type { ManagedItem } from '../../types';
import { EolStatusCell } from './EolStatusCell';
import { SecurityBadgeCell } from './SecurityBadgeCell';

interface ItemRowProps {
  item: ManagedItem;
  hubNode: string;
  chosenVersion?: string;
  onSelectVersion: (itemKey: string, version: string) => void;
  onOpenBrokenLinkage: (pkgName: string, details: string) => void;
  onOpenUpdateModal: (item: ManagedItem, targetVersion: string) => void;
  onSkipItem: (item: ManagedItem, targetVersion: string) => void;
  onUnskipItem: (item: ManagedItem) => void;
  onRollbackService: (nodeName: string, serviceName: string) => void;
}

/**
 * Renders a single managed component row with version selector and remediation actions.
 */
export const ItemRow: React.FC<ItemRowProps> = ({
  item,
  hubNode,
  chosenVersion,
  onSelectVersion,
  onOpenBrokenLinkage,
  onOpenUpdateModal,
  onSkipItem,
  onUnskipItem,
  onRollbackService,
}) => {
  const nodeName = item.node || hubNode || 'local';
  const itemKey = getItemKey(item, hubNode);
  const { tags, selectedVer } = resolveTargetVersion(item, chosenVersion);

  const dotClass =
    item.crit_count > 0 || item.broken_linkage || item.eol?.status === 'expired'
      ? 'red'
      : item.high_count > 0 || item.eol?.status === 'expiring_soon' || item.outdated
        ? 'amber'
        : 'green';

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
    <tr className="border-b border-slate-700 last:border-b-0 hover:bg-[#263449] transition-colors">
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
        <SecurityBadgeCell item={item} onOpenBrokenLinkage={onOpenBrokenLinkage} />
      </td>

      <td className="px-4 py-3.5 align-middle">
        <EolStatusCell item={item} />
      </td>

      <td className="px-4 py-3.5 align-middle">
        <select
          className="ver-select"
          aria-label={`Target version for ${item.name}`}
          value={selectedVer}
          onChange={(e) => onSelectVersion(itemKey, e.target.value)}
        >
          {tags.map((t) => (
            <option key={t} value={t}>
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
};
