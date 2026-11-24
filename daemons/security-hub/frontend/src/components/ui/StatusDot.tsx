import React from 'react';
import { cn } from '../../lib/cn';

export type DotStatus = 'green' | 'amber' | 'red' | 'scanning';

export interface StatusDotProps extends React.HTMLAttributes<HTMLSpanElement> {
  status: DotStatus;
}

/**
 * Reusable status indicator dot (`green`, `amber`, `red`, `scanning`).
 */
export const StatusDot = React.forwardRef<HTMLSpanElement, StatusDotProps>(
  ({ status, className, ...props }, ref) => (
    <span ref={ref} className={cn('dot', status, className)} {...props} />
  )
);
StatusDot.displayName = 'StatusDot';
