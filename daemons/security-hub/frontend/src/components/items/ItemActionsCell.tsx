import type React from 'react';
import { isItemUpdatable, isSafeHttpUrl } from '../../lib/domain';
import type { ManagedItem } from '../../types';
import { Badge, Button } from '../ui';

export interface ItemActionsCellProps {
  item: ManagedItem;
  nodeName: string;
  selectedVer: string;
  onOpenUpdateModal: (item: ManagedItem, targetVersion: string) => void;
  onSkipItem: (item: ManagedItem, targetVersion: string) => void;
  onUnskipItem: (item: ManagedItem) => void;
  onRollbackService: (nodeName: string, serviceName: string) => void;
}

/**
 * Renders remediation controls (Update / Upgrade & Fix, Skip / Unskip, Rollback, Release Notes) for an item row.
 */
export const ItemActionsCell: React.FC<ItemActionsCellProps> = ({
  item,
  nodeName,
  selectedVer,
  onOpenUpdateModal,
  onSkipItem,
  onUnskipItem,
  onRollbackService,
}) => {
  const updatable = isItemUpdatable(item);

  return (
    <div className="flex gap-1.5 items-center flex-wrap">
      {updatable && (
        <>
          <Button
            variant={item.crit_count > 0 || item.broken_linkage ? 'danger' : 'primary'}
            onClick={() => onOpenUpdateModal(item, selectedVer)}
          >
            {item.broken_linkage ? 'Upgrade & Fix' : 'Update'}
          </Button>

          {item.skipped ? (
            <>
              <Badge tone="skip">Skipped {item.skipped_version}</Badge>
              <Button variant="ghost" onClick={() => onUnskipItem(item)}>
                Unskip
              </Button>
            </>
          ) : (
            item.outdated && (
              <Button variant="ghost" onClick={() => onSkipItem(item, selectedVer)}>
                Skip
              </Button>
            )
          )}

          {item.has_rollback && (
            <Button variant="ghost" onClick={() => onRollbackService(nodeName, item.name)}>
              Rollback ({item.rollback_version})
            </Button>
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
  );
};
