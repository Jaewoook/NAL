import { useMutation } from '@tanstack/react-query';
import { type MutableRefObject, useCallback } from 'react';
import { toast } from 'sonner';
import {
  type AxiosRequestConfig,
  apiClient,
  getAxiosErrorMessage,
  hubApi,
  isAxiosUnauthorized,
} from '../lib/http';
import type { ManagedItem, PendingUpdateRequest } from '../types';
import type { ConfirmDialogOptions } from './useConfirmDialog';

interface UseDashboardActionsOptions {
  hubNode: string;
  currentNodeFilter: string;
  authEpochRef: MutableRefObject<number>;
  onUnauthorized: () => void;
  refreshDashboard: () => Promise<void>;
  onOpenTaskLog: (taskId: string) => void;
  onResetNodeFilter: () => void;
  requestConfirm: (options: ConfirmDialogOptions) => Promise<boolean>;
}

/**
 * Encapsulates dashboard mutations (updates, rollbacks, skips, and node registry CRUD) via TanStack Query.
 */
export function useDashboardActions({
  hubNode,
  currentNodeFilter,
  authEpochRef,
  onUnauthorized,
  refreshDashboard,
  onOpenTaskLog,
  onResetNodeFilter,
  requestConfirm,
}: UseDashboardActionsOptions) {
  const apiMutation = useMutation({
    onMutate: () => ({ epoch: authEpochRef.current }),
    mutationFn: async ({ config }: { config: AxiosRequestConfig; errPrefix: string }) => {
      const res = await apiClient.request(config);
      return res.data;
    },
    onSuccess: (_data, _variables, context) => {
      if (context && context.epoch !== authEpochRef.current) return;
      void refreshDashboard();
    },
    onError: (err, variables, context) => {
      if (context && context.epoch !== authEpochRef.current) return;
      if (isAxiosUnauthorized(err)) {
        onUnauthorized();
        return;
      }
      toast.error(`${variables.errPrefix}: ${getAxiosErrorMessage(err)}`);
    },
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

  const approveNode = useCallback(
    (name: string) => {
      apiMutation.mutate({
        config: hubApi.approveNodeConfig(name),
        errPrefix: 'Failed to approve node',
      });
    },
    [apiMutation]
  );

  const rejectNode = useCallback(
    async (name: string) => {
      const confirmed = await requestConfirm({
        title: 'Dismiss Agent Registration',
        description: `Dismiss pending registration for "${name}"?`,
        confirmLabel: 'Dismiss',
        danger: true,
      });
      if (!confirmed) return;

      apiMutation.mutate({
        config: hubApi.rejectNodeConfig(name),
        errPrefix: 'Failed to dismiss node',
      });
    },
    [apiMutation, requestConfirm]
  );

  const saveNode = useCallback(
    async (name: string, url: string, token: string): Promise<boolean> => {
      const epoch = authEpochRef.current;
      try {
        await apiMutation.mutateAsync({
          config: hubApi.saveNodeConfig(name, url, token),
          errPrefix: 'Failed to save node',
        });
        if (epoch !== authEpochRef.current) return false;
        toast.success(`Saved node "${name}"`);
        return true;
      } catch {
        return false;
      }
    },
    [apiMutation, authEpochRef]
  );

  const deleteNode = useCallback(
    async (name: string) => {
      const confirmed = await requestConfirm({
        title: 'Remove Compute Node',
        description: `Remove compute node "${name}" from the registry?`,
        confirmLabel: 'Remove Node',
        danger: true,
      });
      if (!confirmed) return;

      apiMutation.mutate(
        {
          config: hubApi.deleteNodeConfig(name),
          errPrefix: 'Failed to remove node',
        },
        {
          onSuccess: () => {
            if (currentNodeFilter === name) onResetNodeFilter();
          },
        }
      );
    },
    [apiMutation, currentNodeFilter, onResetNodeFilter, requestConfirm]
  );

  return {
    confirmUpdate,
    rollbackService,
    skipItem,
    unskipItem,
    approveNode,
    rejectNode,
    saveNode,
    deleteNode,
  };
}
