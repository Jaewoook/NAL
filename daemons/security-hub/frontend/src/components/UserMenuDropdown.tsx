import { Menu, MenuButton, MenuItem, MenuItems } from '@headlessui/react';
import type React from 'react';

const AUTHENTIK_LIBRARY_URL = 'https://auth.jaewook.dev/if/user/#/library';

export interface UserMenuDropdownProps {
  username: string;
  authMethod: string;
  onRegisterPasskey: () => void;
  onLogout: () => void;
}

/**
 * Accessible Headless UI user account dropdown with SSO portal link, passkey registration, and logout.
 */
export const UserMenuDropdown: React.FC<UserMenuDropdownProps> = ({
  username,
  authMethod,
  onRegisterPasskey,
  onLogout,
}) => {
  return (
    <Menu as="div" className="relative inline-block" id="user-dropdown">
      <MenuButton
        id="user-chip-btn"
        className="inline-flex items-center gap-2 bg-slate-800 border border-slate-700 px-3.5 py-1.5 rounded-full text-slate-50 text-[13px] font-semibold cursor-pointer transition-all hover:bg-surface-hover hover:border-sky-400"
      >
        <span id="auth-username">{username}</span>
        <span className="text-[10px] text-slate-400">▾</span>
      </MenuButton>

      <MenuItems
        id="user-menu"
        className="absolute top-[calc(100%+8px)] right-0 bg-surface-header border border-slate-700 rounded-[10px] min-w-[210px] py-1.5 shadow-[0_10px_25px_-5px_rgba(0,0,0,0.65),0_8px_10px_-6px_rgba(0,0,0,0.5)] z-50 flex flex-col focus:outline-none"
      >
        <div className="px-4 pt-2 pb-2.5 border-b border-slate-700 text-xs text-slate-400">
          <span className="block text-[11px] uppercase tracking-wider text-slate-500 mb-0.5">
            Signed in as
          </span>
          <strong id="auth-user-detail" className="text-slate-100">
            {username} ({(authMethod || 'sso').toUpperCase()})
          </strong>
        </div>
        <MenuItem>
          <a
            className="flex items-center gap-2.5 px-4 py-2.25 text-slate-50 no-underline text-[13px] font-medium data-[focus]:bg-surface-hover data-[focus]:text-white"
            href={AUTHENTIK_LIBRARY_URL}
            target="_blank"
            rel="noopener noreferrer"
          >
            <span className="text-[13px] w-4 inline-flex justify-center">⊞</span>
            <span>Dashboard</span>
            <span className="ml-auto text-[11px] text-slate-400">↗</span>
          </a>
        </MenuItem>
        <MenuItem>
          <button
            type="button"
            className="flex items-center gap-2.5 px-4 py-2.25 text-slate-50 text-[13px] font-medium bg-transparent border-0 w-full text-left cursor-pointer data-[focus]:bg-surface-hover data-[focus]:text-white"
            onClick={onRegisterPasskey}
          >
            <span className="text-[13px] w-4 inline-flex justify-center">🔑</span>
            <span>Register Passkey</span>
          </button>
        </MenuItem>
        <div className="h-px bg-slate-700 my-1.5" />
        <MenuItem>
          <button
            type="button"
            className="flex items-center gap-2.5 px-4 py-2.25 text-red-400 text-[13px] font-medium bg-transparent border-0 w-full text-left cursor-pointer data-[focus]:bg-red-500/15 data-[focus]:text-red-300"
            onClick={onLogout}
          >
            <span className="text-[13px] w-4 inline-flex justify-center">⎋</span>
            <span>Sign out</span>
          </button>
        </MenuItem>
      </MenuItems>
    </Menu>
  );
};
