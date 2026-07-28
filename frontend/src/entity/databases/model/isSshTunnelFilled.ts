import type { SshTunnel } from './SshTunnel';

export const isSshTunnelFilled = (sshTunnel: SshTunnel, isSecretRequired: boolean): boolean => {
  if (!sshTunnel.host?.trim()) return false;
  if (!sshTunnel.port) return false;
  if (!sshTunnel.username?.trim()) return false;

  if (isSecretRequired && !sshTunnel.password && !sshTunnel.privateKey) return false;

  return sshTunnel.shouldSkipHostKeyCheck || !!sshTunnel.hostKeyFingerprint?.trim();
};
