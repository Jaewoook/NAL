import type React from 'react';
import { Button } from './ui/Button';

interface LoginViewProps {
  onPasskeyLogin: () => void;
}

/**
 * Renders the offline-resilient OIDC and Passkey authentication view.
 */
export const LoginView: React.FC<LoginViewProps> = ({ onPasskeyLogin }) => {
  return (
    <div
      id="view-login"
      className="bg-slate-800 border border-slate-700 rounded-xl p-5 max-w-[460px] mx-auto my-12 text-center"
    >
      <div className="inline-block mb-3 bg-gradient-to-br from-sky-400 to-indigo-400 text-[#0b1120] px-2 py-1 rounded-md text-xs font-extrabold">
        NAL SECURITY
      </div>
      <h3 className="text-lg font-bold">NAL Security Hub</h3>
      <p className="text-slate-400 text-[13px] mb-5">
        Restricted to authorized NAL administrators.
      </p>

      <a
        href="/api/auth/oidc/login"
        className="btn btn-primary block w-full py-2.75 no-underline mb-3"
      >
        🔐 Sign in with NAL Account (Authentik SSO)
      </a>

      <div className="my-3.5 text-slate-400 text-xs">— OR EMERGENCY / OFFLINE ACCESS —</div>

      <Button variant="ghost" className="w-full py-2.75 text-slate-50" onClick={onPasskeyLogin}>
        🔑 Sign in with Registered Passkey (TouchID / Hardware Key)
      </Button>

      <p className="text-[11.5px] text-slate-400 mt-4 text-left bg-slate-900 p-2.5 rounded-lg">
        <strong>Offline Resilience:</strong> Passkey verification and active sessions run locally on
        the Mac mini host daemon, remaining accessible even while <code>auth</code> (Authentik) or{' '}
        <code>db</code> (PostgreSQL) is restarting.
      </p>
    </div>
  );
};
