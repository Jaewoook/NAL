import { useMutation } from '@tanstack/react-query';
import type { MutableRefObject } from 'react';
import { toast } from 'sonner';
import {
  type AxiosRequestConfig,
  apiClient,
  getAxiosErrorMessage,
  isAxiosUnauthorized,
} from '../lib/http';

export interface UseApiMutationOptions {
  authEpochRef: MutableRefObject<number>;
  onUnauthorized: () => void;
  refreshDashboard: () => Promise<void>;
}

export interface ApiMutationVariables {
  config: AxiosRequestConfig;
  errPrefix: string;
}

/**
 * Shared epoch-aware TanStack `useMutation` wrapper that refreshes dashboard data on success
 * and centralizes 401 session invalidation and error notifications.
 */
export function useApiMutation({
  authEpochRef,
  onUnauthorized,
  refreshDashboard,
}: UseApiMutationOptions) {
  return useMutation({
    onMutate: () => ({ epoch: authEpochRef.current }),
    mutationFn: async ({ config }: ApiMutationVariables) => {
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
}
