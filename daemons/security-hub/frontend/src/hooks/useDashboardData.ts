import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { getItemSortRank } from '../lib/domain';
import { hubApi, isAxiosUnauthorized } from '../lib/http';
import type { DashboardResponse, NodeInfo, TabType } from '../types';

interface UseDashboardDataOptions {
  authenticated: boolean;
  pollFallback: boolean;
  currentTab: TabType;
  onUnauthorized: () => void;
}

/**
 * Fetches `/api/dashboard`, coordinates fallback polling, and derives filtered node/item views.
 */
export function useDashboardData({
  authenticated,
  pollFallback,
  currentTab,
  onUnauthorized,
}: UseDashboardDataOptions) {
  const queryClient = useQueryClient();
  const [currentNodeFilter, setCurrentNodeFilter] = useState<string>('all');

  const dashboardQuery = useQuery({
    queryKey: ['dashboard'],
    enabled: authenticated,
    refetchInterval: pollFallback ? 2000 : false,
    queryFn: async (): Promise<DashboardResponse> => {
      try {
        const { data } = await hubApi.getDashboard();
        return data;
      } catch (err) {
        if (isAxiosUnauthorized(err)) {
          onUnauthorized();
        }
        throw err;
      }
    },
  });

  const refreshDashboard = useCallback(
    () => queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
    [queryClient]
  );

  const dashboardData = dashboardQuery.data ?? null;
  const hubNode = dashboardData?.hub_node || 'local';

  const allNodes: NodeInfo[] = useMemo(() => {
    if (dashboardData?.nodes) return dashboardData.nodes;
    return [{ name: hubNode, role: 'hub', status: 'approved', online: true }];
  }, [dashboardData, hubNode]);

  const approvedNodes = useMemo(
    () => allNodes.filter((n) => !n.status || n.status === 'approved'),
    [allNodes]
  );

  const pendingNodesCount = useMemo(
    () => allNodes.filter((n) => n.status === 'pending').length,
    [allNodes]
  );

  useEffect(() => {
    if (!dashboardData || currentNodeFilter === 'all') return;
    const stillApproved = approvedNodes.some(
      (n) => n.name.toLowerCase() === currentNodeFilter.toLowerCase()
    );
    if (!stillApproved) {
      setCurrentNodeFilter('all');
    }
  }, [dashboardData, approvedNodes, currentNodeFilter]);

  const nodeFilteredItems = useMemo(() => {
    const allItems = dashboardData?.scan?.items || [];
    if (currentNodeFilter === 'all') return allItems;
    return allItems.filter((item) => (item.node || hubNode) === currentNodeFilter);
  }, [dashboardData, currentNodeFilter, hubNode]);

  const tabCounts = useMemo(
    () => ({
      docker: nodeFilteredItems.filter((i) => i.target_type === 'docker').length,
      brew: nodeFilteredItems.filter((i) => i.target_type === 'brew' || i.target_type === 'apt')
        .length,
      daemons: nodeFilteredItems.filter(
        (i) => i.target_type === 'daemon' || i.target_type === 'macos'
      ).length,
      logs: (dashboardData?.recent_tasks || []).length,
    }),
    [nodeFilteredItems, dashboardData]
  );

  const sortedTabItems = useMemo(() => {
    const filtered = nodeFilteredItems.filter((item) => {
      if (currentTab === 'docker') return item.target_type === 'docker';
      if (currentTab === 'brew') return item.target_type === 'brew' || item.target_type === 'apt';
      return item.target_type === 'daemon' || item.target_type === 'macos';
    });
    return [...filtered].sort((a, b) => {
      const rankDiff = getItemSortRank(a) - getItemSortRank(b);
      return rankDiff !== 0
        ? rankDiff
        : (a.name || '').localeCompare(b.name || '', undefined, { sensitivity: 'base' });
    });
  }, [nodeFilteredItems, currentTab]);

  return {
    dashboardData,
    hubNode,
    allNodes,
    approvedNodes,
    pendingNodesCount,
    currentNodeFilter,
    setCurrentNodeFilter,
    nodeFilteredItems,
    tabCounts,
    sortedTabItems,
    refreshDashboard,
  };
}
