import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ItemsTable } from '../components/ItemsTable';
import { PendingNodesSection } from '../components/nodes/PendingNodesSection';
import { RegisteredNodesList } from '../components/nodes/RegisteredNodesList';

describe('Node version chips and daemon status', () => {
  it('renders build version as a rounded chip in RegisteredNodesList (active and rejected)', () => {
    render(
      <RegisteredNodesList
        activeNodes={[
          {
            name: 'Axis',
            role: 'hub',
            status: 'approved',
            online: true,
            version: '2026-11-27.16.17',
          },
          {
            name: 'Atlas',
            role: 'agent',
            status: 'approved',
            online: true,
            os_version: 'linux/arm64',
            version: '2026-11-27.15.40',
          },
        ]}
        rejectedNodes={[
          {
            name: 'OldNode',
            role: 'agent',
            status: 'rejected',
            online: false,
            version: '2026-11-20.09.00',
          },
        ]}
        onApproveNode={vi.fn()}
        onDeleteNode={vi.fn()}
      />
    );

    expect(screen.getByText('2026-11-27.16.17')).toHaveClass('rounded-full');
    expect(screen.getByText('2026-11-27.15.40')).toHaveClass('rounded-full');
    expect(screen.getByText('2026-11-20.09.00')).toHaveClass('rounded-full');
  });

  it('renders build version as a rounded chip in PendingNodesSection', () => {
    render(
      <PendingNodesSection
        pendingNodes={[
          {
            name: 'NewNode',
            role: 'agent',
            status: 'pending',
            online: true,
            os_version: 'darwin/arm64',
            version: '2026-11-27.16.10',
          },
        ]}
        onApproveNode={vi.fn()}
        onRejectNode={vi.fn()}
      />
    );

    expect(screen.getByText('2026-11-27.16.10')).toHaveClass('rounded-full');
  });

  it('renders Running and Stopped status chips for server-monitor in ItemsTable', () => {
    render(
      <ItemsTable
        items={[
          {
            node: 'Axis',
            target_type: 'daemon',
            name: 'server-monitor',
            current_version: '2026-11-27.16.22',
            latest_version: '2026-11-27.16.22',
            available_tags: ['2026-11-27.16.22'],
            outdated: false,
            skipped: false,
            broken_linkage: false,
            crit_count: 0,
            high_count: 0,
            eol: { status: 'supported', message: 'Internal NAL daemon' },
            service_status: 'running',
          },
          {
            node: 'Atlas',
            target_type: 'daemon',
            name: 'server-monitor',
            current_version: '2026-11-27.15.00',
            latest_version: '2026-11-27.15.00',
            available_tags: ['2026-11-27.15.00'],
            outdated: false,
            skipped: false,
            broken_linkage: false,
            crit_count: 0,
            high_count: 0,
            eol: { status: 'supported', message: 'Internal NAL daemon' },
            service_status: 'stopped',
          },
        ]}
        hubNode="Axis"
        selectedVersions={{}}
        onSelectVersion={vi.fn()}
        onOpenBrokenLinkage={vi.fn()}
        onOpenUpdateModal={vi.fn()}
        onSkipItem={vi.fn()}
        onUnskipItem={vi.fn()}
        onRollbackService={vi.fn()}
      />
    );

    expect(screen.getByText('Running')).toHaveClass('rounded-full');
    expect(screen.getByText('Stopped')).toHaveClass('rounded-full');
    expect(screen.queryByText(/EoL in/i)).not.toBeInTheDocument();
  });
});
