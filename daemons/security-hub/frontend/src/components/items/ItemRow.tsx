import type React from 'react';
import { getItemKey, resolveTargetVersion } from '../../lib/domain';
import type { ManagedItem } from '../../types';
import { Badge, type DotStatus, StatusDot } from '../ui';
import { EolStatusCell } from './EolStatusCell';
import { ItemActionsCell } from './ItemActionsCell';
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

function getItemStatusDot(item: ManagedItem): DotStatus {
  if (item.crit_count > 0 || item.broken_linkage || item.eol?.status === 'expired') {
    return 'red';
  }
  if (item.high_count > 0 || item.eol?.status === 'expiring_soon' || item.outdated) {
    return 'amber';
  }
  return 'green';
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

  const subType =
    item.target_type === 'brew' || item.target_type === 'apt'
      ? item.target_type
      : item.image_ref || item.target_type;

  return (
    <tr className="border-b border-slate-700 last:border-b-0 hover:bg-surface-hover transition-colors">
      <td className="px-4 py-3.5 align-middle">
        <div className="flex flex-col gap-0.75">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="bg-slate-400/15 text-slate-300 border border-slate-600 text-[11px] px-1.75 py-0.25 rounded font-semibold inline-flex items-center">
              {nodeName}
            </span>
            {item.critical_path && (
              <Badge tone="warn" className="text-[10px] px-1.5 py-0.25">
                Critical Path
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-1.75 font-bold text-[14.5px] text-slate-50 my-0.25">
            <StatusDot status={getItemStatusDot(item)} />
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
          {tags.map((tag) => (
            <option key={tag} value={tag}>
              {tag}
            </option>
          ))}
        </select>
      </td>

      <td className="px-4 py-3.5 align-middle">
        <ItemActionsCell
          item={item}
          nodeName={nodeName}
          selectedVer={selectedVer}
          onOpenUpdateModal={onOpenUpdateModal}
          onSkipItem={onSkipItem}
          onUnskipItem={onUnskipItem}
          onRollbackService={onRollbackService}
        />
      </td>
    </tr>
  );
};
