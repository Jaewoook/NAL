import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import { getAxiosErrorMessage, hubApi, isAxiosUnauthorized, setCsrfToken } from '../lib/http';
import type { SessionResponse } from '../types';

/**
 * Manages session query state, CSRF synchronization, logout, and WebAuthn passkey flows.
 */
export function useAuth() {
  const queryClient = useQueryClient();
  const [authEpoch, setAuthEpoch] = useState(0);
  const authEpochRef = useRef(0);
  const wasAuthenticatedRef = useRef(false);

  const clearCachedSession = useCallback(() => {
    queryClient.setQueryData<SessionResponse>(['session'], (prev) => ({
      ...prev,
      authenticated: false,
      csrf_token: '',
    }));
  }, [queryClient]);

  const resetSession = useCallback(() => {
    wasAuthenticatedRef.current = false;
    authEpochRef.current += 1;
    setAuthEpoch(authEpochRef.current);
    setCsrfToken('');
    queryClient.removeQueries({ queryKey: ['dashboard'] });
  }, [queryClient]);

  useEffect(() => {
    return () => {
      authEpochRef.current += 1;
    };
  }, []);

  const handleUnauthorized = useCallback(() => {
    clearCachedSession();
    resetSession();
    void queryClient.invalidateQueries({ queryKey: ['session'] });
  }, [clearCachedSession, queryClient, resetSession]);

  const sessionQuery = useQuery({
    queryKey: ['session'],
    queryFn: async () => {
      const { data } = await hubApi.getSession();
      return data;
    },
  });

  const authenticated = Boolean(sessionQuery.data?.authenticated);

  useEffect(() => {
    if (!sessionQuery.isFetched) return;
    if (!sessionQuery.data?.authenticated) {
      if (wasAuthenticatedRef.current) {
        resetSession();
      }
      return;
    }
    wasAuthenticatedRef.current = true;
    if (sessionQuery.data.csrf_token) {
      setCsrfToken(sessionQuery.data.csrf_token);
    }
  }, [sessionQuery.data, sessionQuery.isFetched, resetSession]);

  const logout = useCallback(async () => {
    resetSession();
    await hubApi.logout().catch(() => undefined);
    clearCachedSession();
    await queryClient.invalidateQueries({ queryKey: ['session'] });
  }, [clearCachedSession, queryClient, resetSession]);

  const registerPasskey = useCallback(async () => {
    if (!browserSupportsWebAuthn()) {
      toast.error('Passkeys require a WebAuthn-capable browser over HTTPS or localhost.');
      return;
    }
    const epoch = authEpochRef.current;
    try {
      const { data: opts } = await hubApi.beginPasskeyRegister();
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

      await hubApi.finishPasskeyRegister({
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
      const { data: opts } = await hubApi.beginPasskeyLogin();
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
      await hubApi.finishPasskeyLogin({
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
    authEpoch,
    authEpochRef,
    handleUnauthorized,
    logout,
    registerPasskey,
    loginWithPasskey,
  };
}
