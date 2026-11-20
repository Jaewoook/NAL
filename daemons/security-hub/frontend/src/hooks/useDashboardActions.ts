import { useCallback, type MutableRefObject } from 'react';
import { useMutation } from '@tanstack/react-query';
import { toast } from 'sonner';
import {
  apiClient,
  getAxiosErrorMessage,
  isAxiosUnauthorized,
  type AxiosRequestConfig,
} from '../api';
import type { ManagedItem, PendingUpdateRequest } from '../types';

interface UseDashboardActionsOptions {
  hubNode: string;
  currentNodeFilter: string;
  authEpochRef: MutableRefObject<number>;
  onUnauthorized: () => void;
  refreshDashboard: () => Promise<void>;
  onOpenTaskLog: (taskId: string) => void;
  onResetNodeFilter: () => void;
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
          config: {
            url: '/api/update',
            method: 'POST',
            data: {
              node: req.node,
              target_type: req.target_type,
              target_name: req.target_name,
              target_version: req.target_version,
              broken_linkage: req.broken_linkage,
              stateful: req.stateful,
              run_backup: runBackup,
              enable_dead_man: enableDeadMan,
            },
          },
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
      if (!window.confirm(`Roll back ${serviceName} on ${nodeName} to its previous snapshot version and digest?`)) {
        return;
      }
      const epoch = authEpochRef.current;
      try {
        const task = (await apiMutation.mutateAsync({
          config: { url: '/api/rollback', method: 'POST', data: { node: nodeName, service_name: serviceName } },
          errPrefix: 'Rollback failed',
        })) as { id?: string } | null;
        if (epoch !== authEpochRef.current) return;
        onOpenTaskLog(task?.id || '');
      } catch {
        // Error toast handled by apiMutation.onError
      }
    },
    [apiMutation, authEpochRef, onOpenTaskLog]
  );

  const skipItem = useCallback(
    (item: ManagedItem, targetVersion: string) => {
      apiMutation.mutate({
        config: {
          url: '/api/skip',
          method: 'POST',
          data: {
            node: item.node || hubNode || 'local',
            target_type: item.target_type,
            target_name: item.name,
            version: targetVersion,
          },
        },
        errPrefix: 'Failed to skip version',
      });
    },
    [apiMutation, hubNode]
  );

  const unskipItem = useCallback(
    (item: ManagedItem) => {
      apiMutation.mutate({
        config: {
          url: '/api/skip',
          method: 'DELETE',
          params: {
            node: item.node || hubNode || 'local',
            target_type: item.target_type,
            target_name: item.name,
          },
        },
        errPrefix: 'Failed to unskip version',
      });
    },
    [apiMutation, hubNode]
  );

  const approveNode = useCallback(
    (name: string) => {
      apiMutation.mutate({
        config: { url: '/api/nodes/approve', method: 'POST', params: { name } },
        errPrefix: 'Failed to approve node',
      });
    },
    [apiMutation]
  );

  const rejectNode = useCallback(
    (name: string) => {
      if (!window.confirm(`Dismiss registration for "${name}"?`)) return;
      apiMutation.mutate({
        config: { url: '/api/nodes/reject', method: 'POST', params: { name } },
        errPrefix: 'Failed to dismiss node',
      });
    },
    [apiMutation]
  );

  const saveNode = useCallback(
    async (name: string, url: string, token: string): Promise<boolean> => {
      const epoch = authEpochRef.current;
      try {
        await apiMutation.mutateAsync({
          config: { url: '/api/nodes', method: 'POST', data: { name, url, token } },
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
    (name: string) => {
      if (!window.confirm(`Remove compute node "${name}" from the registry?`)) return;
      apiMutation.mutate(
        {
          config: { url: '/api/nodes', method: 'DELETE', params: { name } },
          errPrefix: 'Failed to remove node',
        },
        {
          onSuccess: () => {
            if (currentNodeFilter === name) onResetNodeFilter();
          },
        }
      );
    },
    [apiMutation, currentNodeFilter, onResetNodeFilter]
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
