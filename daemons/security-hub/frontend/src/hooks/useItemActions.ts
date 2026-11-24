import { type MutableRefObject, useCallback } from 'react';
import { hubApi } from '../lib/http';
import type { ManagedItem, PendingUpdateRequest } from '../types';
import { useApiMutation } from './useApiMutation';
import type { ConfirmDialogOptions } from './useConfirmDialog';

export interface UseItemActionsOptions {
  hubNode: string;
  authEpochRef: MutableRefObject<number>;
  onUnauthorized: () => void;
  refreshDashboard: () => Promise<void>;
  onOpenTaskLog: (taskId: string) => void;
  requestConfirm: (options: ConfirmDialogOptions) => Promise<boolean>;
}

/**
 * Encapsulates managed item remediation mutations (`confirmUpdate`, `rollbackService`, `skipItem`, `unskipItem`).
 */
export function useItemActions({
  hubNode,
  authEpochRef,
  onUnauthorized,
  refreshDashboard,
  onOpenTaskLog,
  requestConfirm,
}: UseItemActionsOptions) {
  const apiMutation = useApiMutation({
    authEpochRef,
    onUnauthorized,
    refreshDashboard,
  });

  const confirmUpdate = useCallback(
    async (req: PendingUpdateRequest, runBackup: boolean, enableDeadMan: boolean) => {
      const epoch = authEpochRef.current;
      try {
        const task = (await apiMutation.mutateAsync({
          config: hubApi.updateConfig(req, runBackup, enableDeadMan),
          errPrefix: 'Update failed',
        })) as { id?: string } | null;
        if (epoch !== authEpochRef.current) return;
        onOpenTaskLog(task?.id || '');
      } catch {
        // Error toast handled by apiMutation.onError
      }
    },
    [apiMutation, authEpochRef, onOpenTaskLog]
  );

  const rollbackService = useCallback(
    async (nodeName: string, serviceName: string) => {
      const confirmed = await requestConfirm({
        title: 'Confirm Service Rollback',
        description: `Roll back ${serviceName} on ${nodeName} to its previous snapshot version and digest?`,
        confirmLabel: 'Roll Back',
        danger: true,
      });
      if (!confirmed) return;

      const epoch = authEpochRef.current;
      try {
        const task = (await apiMutation.mutateAsync({
          config: hubApi.rollbackConfig(nodeName, serviceName),
          errPrefix: 'Rollback failed',
        })) as { id?: string } | null;
        if (epoch !== authEpochRef.current) return;
        onOpenTaskLog(task?.id || '');
      } catch {
        // Error toast handled by apiMutation.onError
      }
    },
    [apiMutation, authEpochRef, onOpenTaskLog, requestConfirm]
  );

  const skipItem = useCallback(
    (item: ManagedItem, targetVersion: string) => {
      apiMutation.mutate({
        config: hubApi.skipConfig(
          item.node || hubNode || 'local',
          item.target_type,
          item.name,
          targetVersion
        ),
        errPrefix: 'Failed to skip version',
      });
    },
    [apiMutation, hubNode]
  );

  const unskipItem = useCallback(
    (item: ManagedItem) => {
      apiMutation.mutate({
        config: hubApi.unskipConfig(item.node || hubNode || 'local', item.target_type, item.name),
        errPrefix: 'Failed to unskip version',
      });
    },
    [apiMutation, hubNode]
  );

  return {
    confirmUpdate,
    rollbackService,
    skipItem,
    unskipItem,
  };
}
