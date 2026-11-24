import { act, renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { useConfirmDialog } from '../hooks/useConfirmDialog';

describe('useConfirmDialog', () => {
  it('resolves true when acceptConfirm is called', async () => {
    const { result } = renderHook(() => useConfirmDialog());

    expect(result.current.confirmDialog).toBeNull();

    let resolved: boolean | undefined;
    act(() => {
      void result.current
        .requestConfirm({
          title: 'Confirm Service Rollback',
          description: 'Roll back authentik?',
          confirmLabel: 'Roll Back',
          danger: true,
        })
        .then((val) => {
          resolved = val;
        });
    });

    expect(result.current.confirmDialog).toEqual({
      open: true,
      title: 'Confirm Service Rollback',
      description: 'Roll back authentik?',
      confirmLabel: 'Roll Back',
      danger: true,
    });

    await act(async () => {
      result.current.acceptConfirm();
    });

    expect(resolved).toBe(true);
    expect(result.current.confirmDialog).toBeNull();
  });

  it('resolves false when cancelConfirm is called or when superseded', async () => {
    const { result } = renderHook(() => useConfirmDialog());

    let firstResult: boolean | undefined;
    let secondResult: boolean | undefined;

    await act(async () => {
      void result.current
        .requestConfirm({ title: 'First', description: 'First prompt' })
        .then((val) => {
          firstResult = val;
        });
      void result.current
        .requestConfirm({ title: 'Second', description: 'Second prompt' })
        .then((val) => {
          secondResult = val;
        });
    });

    expect(firstResult).toBe(false);
    expect(result.current.confirmDialog?.title).toBe('Second');

    await act(async () => {
      result.current.cancelConfirm();
    });

    expect(secondResult).toBe(false);
    expect(result.current.confirmDialog).toBeNull();
  });
});
