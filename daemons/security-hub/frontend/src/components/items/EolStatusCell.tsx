import type React from 'react';
import type { ManagedItem } from '../../types';
import { Badge } from '../ui/Badge';

interface EolStatusCellProps {
  item: ManagedItem;
}

/**
 * Renders LTS / End-of-Life window status badges with hover tooltips.
 */
export const EolStatusCell: React.FC<EolStatusCellProps> = ({ item }) => {
  if (!item.eol) {
    return <Badge tone="ok">Supported</Badge>;
  }

  if (item.eol.status === 'expired') {
    const tooltipText =
      item.eol.message ||
      (item.eol.eol_date ? `End of Life reached on ${item.eol.eol_date}` : 'End of Life reached');
    return (
      <div className="tooltip-wrapper">
        <Badge tone="crit">✖ EoL Expired</Badge>
        <div className="tooltip-box">{tooltipText}</div>
      </div>
    );
  }

  if (item.eol.status === 'expiring_soon') {
    const daysRemaining = item.eol.days_remaining ?? 0;
    const tooltipText =
      item.eol.message ||
      `End of Life scheduled in ${daysRemaining}d (${item.eol.eol_date || 'soon'})`;
    return (
      <div className="tooltip-wrapper">
        <Badge tone="warn">⚠ EoL in {daysRemaining}d</Badge>
        <div className="tooltip-box">{tooltipText}</div>
      </div>
    );
  }

  if (item.eol.status === 'unknown') {
    const tooltipText = item.eol.message || 'Lifecycle track not mapped';
    return (
      <div className="tooltip-wrapper">
        <Badge tone="skip">Not Tracked</Badge>
        <div className="tooltip-box">{tooltipText}</div>
      </div>
    );
  }

  if (item.eol.eol_date) {
    return (
      <div className="tooltip-wrapper">
        <Badge tone="ok">Supported</Badge>
        <div className="tooltip-box">Supported until {item.eol.eol_date}</div>
      </div>
    );
  }

  return <Badge tone="ok">Supported</Badge>;
};
