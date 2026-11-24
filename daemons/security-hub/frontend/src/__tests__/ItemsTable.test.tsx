import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ItemsTable } from '../components/ItemsTable';
import type { ManagedItem } from '../types';

afterEach(() => {
  cleanup();
});

const baseDockerItem: ManagedItem = {
  node: 'Axis',
  target_type: 'docker',
  name: 'authentik',
  image_ref: 'ghcr.io/goauthentik/server',
  current_version: '2026.2.0',
  latest_version: '2026.4.1',
  available_tags: ['2026.3.0', '2026.4.1'],
  outdated: true,
  skipped: false,
  broken_linkage: false,
  crit_count: 0,
  high_count: 0,
  has_rollback: true,
  rollback_version: '2026.1.0',
  release_notes_url: 'https://github.com/goauthentik/authentik/releases',
};

describe('ItemsTable, ItemRow, and ItemActionsCell', () => {
  it('renders empty state placeholder when no items match', () => {
    render(
      <ItemsTable
        items={[]}
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

    expect(screen.getByText(/No components on this node\/tab/i)).toBeInTheDocument();
  });

  it('handles version selection, Update, Skip, Rollback, and safe release notes links', () => {
    const onSelectVersion = vi.fn();
    const onOpenUpdateModal = vi.fn();
    const onSkipItem = vi.fn();
    const onRollbackService = vi.fn();

    const { rerender } = render(
      <ItemsTable
        items={[baseDockerItem]}
        hubNode="Axis"
        selectedVersions={{}}
        onSelectVersion={onSelectVersion}
        onOpenBrokenLinkage={vi.fn()}
        onOpenUpdateModal={onOpenUpdateModal}
        onSkipItem={onSkipItem}
        onUnskipItem={vi.fn()}
        onRollbackService={onRollbackService}
      />
    );

    const select = screen.getByLabelText('Target version for authentik') as HTMLSelectElement;
    expect(select.value).toBe('2026.4.1');

    fireEvent.change(select, { target: { value: '2026.3.0' } });
    expect(onSelectVersion).toHaveBeenCalledWith('Axis:docker:authentik', '2026.3.0');

    rerender(
      <ItemsTable
        items={[baseDockerItem]}
        hubNode="Axis"
        selectedVersions={{ 'Axis:docker:authentik': '2026.3.0' }}
        onSelectVersion={onSelectVersion}
        onOpenBrokenLinkage={vi.fn()}
        onOpenUpdateModal={onOpenUpdateModal}
        onSkipItem={onSkipItem}
        onUnskipItem={vi.fn()}
        onRollbackService={onRollbackService}
      />
    );

    const updateBtn = screen.getByRole('button', { name: 'Update' });
    expect(updateBtn).toHaveClass('btn-primary');
    fireEvent.click(updateBtn);
    expect(onOpenUpdateModal).toHaveBeenCalledWith(baseDockerItem, '2026.3.0');

    fireEvent.click(screen.getByRole('button', { name: 'Skip' }));
    expect(onSkipItem).toHaveBeenCalledWith(baseDockerItem, '2026.3.0');

    fireEvent.click(screen.getByRole('button', { name: 'Rollback (2026.1.0)' }));
    expect(onRollbackService).toHaveBeenCalledWith('Axis', 'authentik');

    const notesLink = screen.getByRole('link', { name: /Notes/i });
    expect(notesLink).toHaveAttribute('href', 'https://github.com/goauthentik/authentik/releases');
  });

  it('renders Upgrade & Fix danger button, Unskip action, and filters unsafe javascript: URLs', () => {
    const onOpenBrokenLinkage = vi.fn();
    const onOpenUpdateModal = vi.fn();
    const onUnskipItem = vi.fn();

    const brokenSkippedPkg: ManagedItem = {
      node: 'Axis',
      target_type: 'brew',
      name: 'ffmpeg',
      current_version: '7.0.1',
      latest_version: '7.1.0',
      outdated: true,
      skipped: true,
      skipped_version: '7.1.0',
      broken_linkage: true,
      linkage_details: 'Library not loaded: libdav1d.7.dylib',
      crit_count: 0,
      high_count: 0,
      release_notes_url: 'javascript:alert(document.cookie)',
    };

    render(
      <ItemsTable
        items={[brokenSkippedPkg]}
        hubNode="Axis"
        selectedVersions={{}}
        onSelectVersion={vi.fn()}
        onOpenBrokenLinkage={onOpenBrokenLinkage}
        onOpenUpdateModal={onOpenUpdateModal}
        onSkipItem={vi.fn()}
        onUnskipItem={onUnskipItem}
        onRollbackService={vi.fn()}
      />
    );

    const row = screen.getByText('ffmpeg').closest('tr');
    if (!row) throw new Error('expected ffmpeg table row');
    const upgradeBtn = within(row).getByRole('button', { name: 'Upgrade & Fix' });
    expect(upgradeBtn).toHaveClass('btn-danger');
    fireEvent.click(upgradeBtn);
    expect(onOpenUpdateModal).toHaveBeenCalledWith(brokenSkippedPkg, '7.1.0');

    expect(within(row).getByText('Skipped 7.1.0')).toBeInTheDocument();
    expect(within(row).queryByRole('button', { name: 'Skip' })).not.toBeInTheDocument();

    fireEvent.click(within(row).getByRole('button', { name: 'Unskip' }));
    expect(onUnskipItem).toHaveBeenCalledWith(brokenSkippedPkg);

    fireEvent.click(within(row).getByRole('button', { name: /Broken Linkage/i }));
    expect(onOpenBrokenLinkage).toHaveBeenCalledWith(
      'ffmpeg',
      'Library not loaded: libdav1d.7.dylib'
    );

    // Unsafe javascript: scheme MUST NOT render an anchor
    expect(within(row).queryByRole('link', { name: /Notes/i })).not.toBeInTheDocument();
  });
});
