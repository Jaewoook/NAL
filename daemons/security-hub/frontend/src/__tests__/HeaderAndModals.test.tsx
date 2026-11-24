import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConfirmModal } from '../components/ConfirmModal';
import { Header } from '../components/Header';
import { NodeBar } from '../components/NodeBar';
import { ScanNodeModal } from '../components/ScanNodeModal';
import { UpdateModal } from '../components/UpdateModal';
import type { NodeInfo, PendingUpdateRequest } from '../types';

const sampleNodes: NodeInfo[] = [
  { name: 'Axis', role: 'hub', status: 'approved', online: true },
  { name: 'Atlas', role: 'agent', status: 'approved', online: true, url: 'http://atlas.lan:10247' },
];

afterEach(() => {
  cleanup();
});

describe('Header & UserMenuDropdown', () => {
  it('hides action controls when unauthenticated', () => {
    render(
      <Header
        authenticated={false}
        username=""
        authMethod=""
        pendingNodesCount={2}
        isScanning={false}
        scanProgressText=""
        onOpenNodesModal={vi.fn()}
        onOpenLogsTab={vi.fn()}
        onOpenScanNodeModal={vi.fn()}
        onTriggerFullScan={vi.fn()}
        onRegisterPasskey={vi.fn()}
        onLogout={vi.fn()}
      />
    );

    expect(screen.getByText('Security Hub')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Scan Now/i })).not.toBeInTheDocument();
  });

  it('renders pending banner, scan controls, and user dropdown actions', async () => {
    const onOpenNodesModal = vi.fn();
    const onOpenLogsTab = vi.fn();
    const onOpenScanNodeModal = vi.fn();
    const onTriggerFullScan = vi.fn();
    const onRegisterPasskey = vi.fn();
    const onLogout = vi.fn();

    const { rerender } = render(
      <Header
        authenticated={true}
        username="jaewook"
        authMethod="passkey"
        pendingNodesCount={3}
        isScanning={false}
        scanProgressText=""
        onOpenNodesModal={onOpenNodesModal}
        onOpenLogsTab={onOpenLogsTab}
        onOpenScanNodeModal={onOpenScanNodeModal}
        onTriggerFullScan={onTriggerFullScan}
        onRegisterPasskey={onRegisterPasskey}
        onLogout={onLogout}
      />
    );

    const pendingBanner = screen.getByRole('button', { name: /3 Pending Node\(s\)/i });
    fireEvent.click(pendingBanner);
    expect(onOpenNodesModal).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: /Task Logs/i }));
    expect(onOpenLogsTab).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: /Scan Single Node/i }));
    expect(onOpenScanNodeModal).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: /Scan Now/i }));
    expect(onTriggerFullScan).toHaveBeenCalledTimes(1);

    // Open Headless UI user menu
    fireEvent.click(screen.getByRole('button', { name: /jaewook/i }));
    expect(await screen.findByText('jaewook (PASSKEY)')).toBeInTheDocument();
    expect(screen.getByRole('menuitem', { name: /Dashboard/i })).toHaveAttribute(
      'href',
      'https://auth.jaewook.dev/if/user/#/library'
    );

    fireEvent.click(screen.getByRole('menuitem', { name: /Register Passkey/i }));
    expect(onRegisterPasskey).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: /jaewook/i }));
    fireEvent.click(await screen.findByRole('menuitem', { name: /Sign out/i }));
    expect(onLogout).toHaveBeenCalledTimes(1);

    // Verify active scan state disables scan buttons and shows progress pill
    rerender(
      <Header
        authenticated={true}
        username="jaewook"
        authMethod="passkey"
        pendingNodesCount={0}
        isScanning={true}
        scanProgressText="[Atlas] Scanning packages..."
        onOpenNodesModal={onOpenNodesModal}
        onOpenLogsTab={onOpenLogsTab}
        onOpenScanNodeModal={onOpenScanNodeModal}
        onTriggerFullScan={onTriggerFullScan}
        onRegisterPasskey={onRegisterPasskey}
        onLogout={onLogout}
      />
    );

    expect(screen.getByText('[Atlas] Scanning packages...')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Scan Single Node/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Scanning\.\.\./i })).toBeDisabled();
  });
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

  it('configures stateful Docker backup and dead-man options and passes them on confirm', async () => {
    const onConfirm = vi.fn();
    const dockerReq: PendingUpdateRequest = {
      node: 'Axis',
      target_type: 'docker',
      target_name: 'postgres',
      current_version: '16.2',
      target_version: '16.4',
      broken_linkage: false,
      stateful: true,
    };

    render(<UpdateModal request={dockerReq} onConfirm={onConfirm} onClose={vi.fn()} />);

    expect(await screen.findByText(/Save Rollback Snapshot/i)).toBeInTheDocument();
    const deadManChk = document.getElementById('chk-deadman') as HTMLInputElement;
    const backupChk = document.getElementById('chk-backup') as HTMLInputElement;
    expect(deadManChk.checked).toBe(true);
    expect(backupChk.checked).toBe(true);

    fireEvent.click(deadManChk);
    fireEvent.click(screen.getByRole('button', { name: /Pull & Apply Update/i }));

    expect(onConfirm).toHaveBeenCalledWith(dockerReq, true, false);
  });
});

describe('ConfirmModal', () => {
  it('invokes confirm and cancel callbacks cleanly', async () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(
      <ConfirmModal
        state={{
          open: true,
          title: 'Remove Compute Node',
          description: 'Remove compute node "Atlas"?',
          confirmLabel: 'Remove Node',
          danger: true,
        }}
        onConfirm={onConfirm}
        onCancel={onCancel}
      />
    );

    const confirmBtn = await screen.findByRole('button', { name: 'Remove Node' });
    expect(confirmBtn).toHaveClass('btn-danger');
    fireEvent.click(confirmBtn);
    expect(onConfirm).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });
});
