import { useCallback, useEffect, useRef } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser';
import { toast } from 'sonner';
import { apiClient, getAxiosErrorMessage, isAxiosUnauthorized, setCsrfToken } from '../api';
import type { SessionResponse } from '../types';

interface PasskeyRegisterBeginResp {
  challenge: string;
  rp_id?: string;
  user: string;
}

interface PasskeyLoginBeginResp {
  challenge: string;
  rp_id?: string;
  allow_credentials?: string[] | null;
}

interface UseAuthOptions {
  onSessionReset: () => void;
}

/**
 * Manages session query state, CSRF synchronization, logout, and WebAuthn passkey flows.
 */
export function useAuth({ onSessionReset }: UseAuthOptions) {
  const queryClient = useQueryClient();
  const authEpochRef = useRef(0);
  const onSessionResetRef = useRef(onSessionReset);

  useEffect(() => {
    onSessionResetRef.current = onSessionReset;
  }, [onSessionReset]);

  const resetSession = useCallback(() => {
    authEpochRef.current += 1;
    setCsrfToken('');
    queryClient.removeQueries({ queryKey: ['dashboard'] });
    onSessionResetRef.current();
  }, [queryClient]);

  useEffect(() => {
    return () => {
      authEpochRef.current += 1;
    };
  }, []);

  const clearCachedSession = useCallback(() => {
    queryClient.setQueryData<SessionResponse>(['session'], (prev) => ({
      ...prev,
      authenticated: false,
      csrf_token: '',
    }));
  }, [queryClient]);

  const handleUnauthorized = useCallback(() => {
    clearCachedSession();
    resetSession();
    void queryClient.invalidateQueries({ queryKey: ['session'] });
  }, [clearCachedSession, queryClient, resetSession]);

  const sessionQuery = useQuery({
    queryKey: ['session'],
    queryFn: async () => {
      const { data } = await apiClient.get<SessionResponse>('/api/auth/session');
      return data;
    },
  });

  const authenticated = Boolean(sessionQuery.data?.authenticated);

  useEffect(() => {
    if (!sessionQuery.isFetched) return;
    if (!sessionQuery.data?.authenticated) {
      resetSession();
      return;
    }
    if (sessionQuery.data.csrf_token) {
      setCsrfToken(sessionQuery.data.csrf_token);
    }
  }, [sessionQuery.data, sessionQuery.isFetched, resetSession]);

  const logout = useCallback(async () => {
    authEpochRef.current += 1;
    onSessionResetRef.current();
    await apiClient.post('/api/auth/logout').catch(() => undefined);
    clearCachedSession();
    resetSession();
    await queryClient.invalidateQueries({ queryKey: ['session'] });
  }, [clearCachedSession, queryClient, resetSession]);

  const registerPasskey = useCallback(async () => {
    if (!browserSupportsWebAuthn()) {
      toast.error('Passkeys require a WebAuthn-capable browser over HTTPS or localhost.');
      return;
    }
    const epoch = authEpochRef.current;
    try {
      const { data: opts } = await apiClient.post<PasskeyRegisterBeginResp>(
        '/api/auth/passkey/register/begin'
      );
      if (epoch !== authEpochRef.current) return;

      const randomUserId = crypto.randomUUID().replace(/-/g, '');
      const attResp = await startRegistration({
        optionsJSON: {
          challenge: opts.challenge,
          rp: { name: 'NAL Security Hub', id: opts.rp_id || window.location.hostname },
          user: { id: randomUserId, name: opts.user, displayName: opts.user },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          timeout: 60000,
        },
      });
      if (epoch !== authEpochRef.current) return;

      await apiClient.post('/api/auth/passkey/register/finish', {
        credential_id: attResp.id,
        label: `${navigator.platform || 'Device'} Passkey`,
        attestation_object: attResp.response.attestationObject,
        client_data_json: attResp.response.clientDataJSON,
      });
      if (epoch !== authEpochRef.current) return;
      toast.success('Passkey registered for offline emergency login!');
    } catch (err) {
      if (epoch !== authEpochRef.current) return;
      if (isAxiosUnauthorized(err)) {
        handleUnauthorized();
        return;
      }
      toast.error(`Passkey registration failed: ${getAxiosErrorMessage(err)}`);
    }
  }, [handleUnauthorized]);

  const loginWithPasskey = useCallback(async () => {
    if (!browserSupportsWebAuthn()) {
      toast.error('Passkeys require a WebAuthn-capable browser over HTTPS or localhost.');
      return;
    }
    try {
      const { data: opts } = await apiClient.post<PasskeyLoginBeginResp>(
        '/api/auth/passkey/login/begin'
      );
      if (!opts.allow_credentials || opts.allow_credentials.length === 0) {
        toast.info(
          'No Passkey registered yet. Sign in via SSO or run "./security-hub auth login-link" first.'
        );
        return;
      }
      const assertion = await startAuthentication({
        optionsJSON: {
          challenge: opts.challenge,
          rpId: opts.rp_id || window.location.hostname,
          allowCredentials: opts.allow_credentials.map((id) => ({ id, type: 'public-key' })),
          timeout: 60000,
        },
      });
      await apiClient.post('/api/auth/passkey/login/finish', {
        credential_id: assertion.id,
        authenticator_data: assertion.response.authenticatorData,
        client_data_json: assertion.response.clientDataJSON,
        signature: assertion.response.signature,
      });
      await queryClient.invalidateQueries({ queryKey: ['session'] });
    } catch (err) {
      toast.error(`Passkey login failed: ${getAxiosErrorMessage(err)}`);
    }
  }, [queryClient]);

  const username =
    sessionQuery.data?.username ||
    (sessionQuery.data?.subject ? sessionQuery.data.subject.split('@')[0] : 'admin');

  return {
    sessionChecked: sessionQuery.isFetched,
    authenticated,
    username,
    authMethod: sessionQuery.data?.method || 'sso',
    authEpochRef,
    handleUnauthorized,
    logout,
    registerPasskey,
    loginWithPasskey,
  };
}
