import React from 'react';
import { cn } from '../../lib/cn';

export type BadgeTone = 'ok' | 'warn' | 'crit' | 'skip';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  tone: BadgeTone;
}

/**
 * Reusable status badge primitive (`ok`, `warn`, `crit`, `skip`).
 */
export const Badge = React.forwardRef<HTMLSpanElement, BadgeProps>(
  ({ tone, className, ...props }, ref) => (
    <span ref={ref} className={cn('badge', tone, className)} {...props} />
  )
);
Badge.displayName = 'Badge';
