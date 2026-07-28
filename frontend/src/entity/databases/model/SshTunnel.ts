export interface SshTunnel {
  id: string;
  databaseId: string;

  host: string;
  port: number;
  username: string;

  password?: string;
  privateKey?: string;
  privateKeyPassphrase?: string;

  hostKeyFingerprint: string;
  shouldSkipHostKeyCheck: boolean;
}
