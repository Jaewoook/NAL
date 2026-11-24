import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { AxiosResponse } from 'axios';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NodesModal } from '../components/NodesModal';
import { hubApi } from '../lib/http';
import type { NodeInfo, NodeTestResponse } from '../types';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const sampleNodes: NodeInfo[] = [
  { name: 'Axis', role: 'hub', status: 'approved', online: true },
  {
    name: 'Atlas',
    role: 'agent',
    status: 'approved',
    online: true,
    url: 'http://192.168.1.50:10247',
    os_version: 'Ubuntu 24.04',
  },
  {
    name: 'Aegis',
    role: 'agent',
    status: 'pending',
    online: false,
    url: 'http://192.168.1.60:10247',
    os_version: 'Debian 12',
  },
  {
    name: 'OldAgent',
    role: 'agent',
    status: 'rejected',
    online: false,
    url: 'http://192.168.1.99:10247',
  },
];

describe('NodesModal', () => {
  it('handles pending approve/dismiss and registered/rejected node actions', async () => {
    const onApproveNode = vi.fn();
    const onRejectNode = vi.fn();
    const onDeleteNode = vi.fn();

    render(
      <NodesModal
        open={true}
        nodes={sampleNodes}
        onApproveNode={onApproveNode}
        onRejectNode={onRejectNode}
        onDeleteNode={onDeleteNode}
        onSaveNode={vi.fn().mockResolvedValue(true)}
        onClose={vi.fn()}
      />
    );

    const pendingList = await screen.findByText('Aegis');
    const pendingSection = pendingList.closest('#pending-nodes-section') as HTMLElement;
    expect(pendingSection).toBeInTheDocument();

    fireEvent.click(within(pendingSection).getByRole('button', { name: 'Approve' }));
    expect(onApproveNode).toHaveBeenCalledWith('Aegis');

    fireEvent.click(within(pendingSection).getByRole('button', { name: 'Dismiss' }));
    expect(onRejectNode).toHaveBeenCalledWith('Aegis');

    const registeredList = document.getElementById('nodes-modal-list') as HTMLElement;
    const axisRow = within(registeredList).getByText('Axis').closest('div.flex') as HTMLElement;
    expect(within(axisRow).queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument();

    const atlasRow = within(registeredList).getByText('Atlas').closest('div.flex') as HTMLElement;
    fireEvent.click(within(atlasRow).getByRole('button', { name: 'Remove' }));
    expect(onDeleteNode).toHaveBeenCalledWith('Atlas');

    const rejectedRow = within(registeredList)
      .getByText('OldAgent')
      .closest('div.flex') as HTMLElement;
    fireEvent.click(within(rejectedRow).getByRole('button', { name: 'Re-Approve' }));
    expect(onApproveNode).toHaveBeenCalledWith('OldAgent');
  });

  it('probes agent connectivity via hubApi.testNodeConnection, auto-fills name, and saves node', async () => {
    const testSpy = vi.spyOn(hubApi, 'testNodeConnection').mockResolvedValue({
      data: {
        ok: true,
        latency_ms: 14,
        os_version: 'Ubuntu 24.04.1 LTS',
        info: {
          name: 'Hyperion',
          role: 'agent',
          online: true,
        },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {} as never,
    } as AxiosResponse<NodeTestResponse>);

    const onSaveNode = vi.fn().mockResolvedValue(true);

    render(
      <NodesModal
        open={true}
        nodes={sampleNodes.slice(0, 1)}
        onApproveNode={vi.fn()}
        onRejectNode={vi.fn()}
        onDeleteNode={vi.fn()}
        onSaveNode={onSaveNode}
        onClose={vi.fn()}
      />
    );

    const nameInput = (await screen.findByPlaceholderText('Device Name')) as HTMLInputElement;
    const urlInput = screen.getByPlaceholderText(/LAN Agent URL/i) as HTMLInputElement;
    const tokenInput = screen.getByPlaceholderText(/Shared X-NAL-Node-Token/i) as HTMLInputElement;

    fireEvent.change(urlInput, { target: { value: '  http://192.168.1.77:10247  ' } });
    fireEvent.change(tokenInput, { target: { value: 'secret-tok' } });

    fireEvent.click(screen.getByRole('button', { name: /Test Connection/i }));

    await waitFor(() => {
      expect(testSpy).toHaveBeenCalledWith(
        'http://192.168.1.77:10247',
        'secret-tok',
        expect.any(AbortSignal)
      );
    });

    const resultBox = await screen.findByText(/Connected!/i);
    expect(resultBox.closest('#test-node-result')).toHaveTextContent('(14ms)');
    expect(resultBox.closest('#test-node-result')).toHaveTextContent('OS: Ubuntu 24.04.1 LTS');
    expect(nameInput.value).toBe('Hyperion');

    fireEvent.click(screen.getByRole('button', { name: /\+ Add \/ Save Node/i }));

    await waitFor(() => {
      expect(onSaveNode).toHaveBeenCalledWith(
        'Hyperion',
        'http://192.168.1.77:10247',
        'secret-tok'
      );
    });
    await waitFor(() => {
      expect(nameInput.value).toBe('');
      expect(urlInput.value).toBe('');
    });
  });
});
