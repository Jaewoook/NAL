import React from 'react';
import { cn } from '../../lib/cn';

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost';

const VARIANT_CLASS: Record<ButtonVariant, string> = {
  primary: 'btn-primary',
  secondary: 'btn-secondary',
  danger: 'btn-danger',
  ghost: 'btn-ghost',
};

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant: ButtonVariant;
}

/**
 * Reusable typed button primitive applying Security Hub `.btn` variant classes.
 */
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant, type = 'button', className, ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={cn('btn', VARIANT_CLASS[variant], className)}
      {...props}
    />
  )
);
Button.displayName = 'Button';
