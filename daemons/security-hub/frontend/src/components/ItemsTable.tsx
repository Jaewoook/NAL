import type React from 'react';
import { getItemKey } from '../lib/domain';
import type { ManagedItem } from '../types';
import { ItemRow } from './items/ItemRow';

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

const HEADERS = [
  'Service / Package',
  'Current Version',
  'CVEs & Linkage',
  'LTS / EoL Status',
  'Target Version',
  'Actions',
];

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
    <div
      id="panel-items"
      className="bg-slate-800 border border-slate-700 rounded-xl overflow-x-auto"
    >
      <table className="w-full border-collapse text-[13.5px]">
        <thead>
          <tr>
            {HEADERS.map((h) => (
              <th
                key={h}
                className="text-left px-4 py-3 bg-[#141d2f] text-slate-400 font-semibold text-xs uppercase border-b border-slate-700"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody id="items-tbody">
          {items.length === 0 ? (
            <tr>
              <td colSpan={6} className="text-slate-400 text-[13px] text-center p-7">
                No components on this node/tab (uninstalled or stopped components are ignored
                automatically). Click <strong>↻ Scan Now</strong> to refresh.
              </td>
            </tr>
          ) : (
            items.map((item) => {
              const itemKey = getItemKey(item, hubNode);
              return (
                <ItemRow
                  key={itemKey}
                  item={item}
                  hubNode={hubNode}
                  chosenVersion={selectedVersions[itemKey]}
                  onSelectVersion={onSelectVersion}
                  onOpenBrokenLinkage={onOpenBrokenLinkage}
                  onOpenUpdateModal={onOpenUpdateModal}
                  onSkipItem={onSkipItem}
                  onUnskipItem={onUnskipItem}
                  onRollbackService={onRollbackService}
                />
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
};
