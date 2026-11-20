import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NodeBar } from './NodeBar';
import { ScanNodeModal } from './ScanNodeModal';
import { UpdateModal } from './UpdateModal';
import type { NodeInfo } from '../types';

const sampleNodes: NodeInfo[] = [
  { name: 'Axis', role: 'hub', status: 'approved', online: true },
  { name: 'Atlas', role: 'agent', status: 'approved', online: true, url: 'http://atlas.lan:10247' },
];

afterEach(() => {
  cleanup();
});

describe('NodeBar', () => {
  it('displays scanning badge on actively scanning node chips', () => {
    const onSelect = vi.fn();
    render(
      <NodeBar
        approvedNodes={sampleNodes}
        scanningNodes={['Atlas']}
        currentNodeFilter="all"
        onSelectNodeFilter={onSelect}
        onOpenNodesModal={vi.fn()}
      />
    );

    const atlasBtn = screen.getByRole('button', { name: /Atlas/i });
    expect(atlasBtn).toHaveClass('scanning');
    expect(atlasBtn).toHaveTextContent('Scanning');

    const axisBtn = screen.getByRole('button', { name: /Axis/i });
    expect(axisBtn).not.toHaveClass('scanning');

    fireEvent.click(atlasBtn);
    expect(onSelect).toHaveBeenCalledWith('Atlas');
  });

  it('marks All Nodes pill as scanning when every approved node is scanning', () => {
    render(
      <NodeBar
        approvedNodes={sampleNodes}
        scanningNodes={['Axis', 'Atlas']}
        currentNodeFilter="all"
        onSelectNodeFilter={vi.fn()}
        onOpenNodesModal={vi.fn()}
      />
    );

    const allBtn = screen.getByRole('button', { name: /All Nodes \(2\)/i });
    expect(allBtn).toHaveClass('scanning');
    expect(allBtn).toHaveTextContent('Scanning');
  });
});

describe('ScanNodeModal', () => {
  it('pre-selects current node filter and resets selection when closed', async () => {
    const onStart = vi.fn();
    const onClose = vi.fn();
    const { rerender } = render(
      <ScanNodeModal
        open={true}
        approvedNodes={sampleNodes}
        scanningNodes={[]}
        currentNodeFilter="Atlas"
        isScanActive={false}
        onStartNodeScan={onStart}
        onClose={onClose}
      />
    );

    const atlasRadio = (await screen.findByDisplayValue('Atlas')) as HTMLInputElement;
    expect(atlasRadio.checked).toBe(true);

    fireEvent.click(screen.getByDisplayValue('Axis'));
    expect((screen.getByDisplayValue('Axis') as HTMLInputElement).checked).toBe(true);

    // Closing and reopening with currentNodeFilter="Atlas" must reset back to Atlas
    rerender(
      <ScanNodeModal
        open={false}
        approvedNodes={sampleNodes}
        scanningNodes={[]}
        currentNodeFilter="Atlas"
        isScanActive={false}
        onStartNodeScan={onStart}
        onClose={onClose}
      />
    );
    rerender(
      <ScanNodeModal
        open={true}
        approvedNodes={sampleNodes}
        scanningNodes={[]}
        currentNodeFilter="Atlas"
        isScanActive={false}
        onStartNodeScan={onStart}
        onClose={onClose}
      />
    );

    const reopenedAtlasRadio = (await screen.findByDisplayValue('Atlas')) as HTMLInputElement;
    expect(reopenedAtlasRadio.checked).toBe(true);

    fireEvent.click(screen.getByRole('button', { name: /Start Scan/i }));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onStart).toHaveBeenCalledWith('Atlas');
  });
});

describe('UpdateModal', () => {
  it('hides Docker rollback/backup options for non-Docker targets', () => {
    render(
      <UpdateModal
        request={{
          node: 'Atlas',
          target_type: 'apt',
          target_name: 'openssl',
          current_version: '3.0.13',
          target_version: '3.0.14',
          broken_linkage: false,
          stateful: false,
        }}
        onConfirm={vi.fn()}
        onClose={vi.fn()}
      />
    );

    expect(screen.queryByText(/Save Rollback Snapshot/i)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Apply Package Upgrade/i })).toBeInTheDocument();
  });
});
