import { InfoCircleOutlined } from '@ant-design/icons';
import { Checkbox, Input, InputNumber, Select, Switch, Tooltip } from 'antd';
import { useState } from 'react';

import { DatabaseType, type SshTunnel } from '../../../../entity/databases';

type SshTunnelAuthMethod = 'password' | 'privateKey';

interface Props {
  databaseType: DatabaseType;
  sshTunnel?: SshTunnel;
  onSshTunnelChange: (sshTunnel?: SshTunnel) => void;
}

const DEFAULT_SSH_PORT = 22;

const createEmptySshTunnel = (): SshTunnel =>
  ({ port: DEFAULT_SSH_PORT, shouldSkipHostKeyCheck: false }) as SshTunnel;

const detectAuthMethod = (sshTunnel?: SshTunnel): SshTunnelAuthMethod =>
  sshTunnel?.privateKey ? 'privateKey' : 'password';

export const EditSshTunnelComponent = ({ databaseType, sshTunnel, onSshTunnelChange }: Props) => {
  const [authMethod, setAuthMethod] = useState<SshTunnelAuthMethod>(detectAuthMethod(sshTunnel));

  const toggleSshTunnel = (isEnabled: boolean) => {
    onSshTunnelChange(isEnabled ? createEmptySshTunnel() : undefined);
  };

  const updateSshTunnel = (patch: Partial<SshTunnel>) => {
    if (!sshTunnel) return;

    onSshTunnelChange({ ...sshTunnel, ...patch });
  };

  const changeAuthMethod = (method: SshTunnelAuthMethod) => {
    setAuthMethod(method);

    updateSshTunnel(
      method === 'password'
        ? { privateKey: '', privateKeyPassphrase: '' }
        : { password: '', privateKey: sshTunnel?.privateKey || '' },
    );
  };

  if (databaseType === DatabaseType.POSTGRES_PHYSICAL) return null;

  const isSshTunnelEnabled = !!sshTunnel;

  return (
    <div className="mt-5">
      <div className="mb-3 flex items-center">
        <Switch size="small" checked={isSshTunnelEnabled} onChange={toggleSshTunnel} />

        <span className="ml-2">Connect through SSH tunnel</span>

        <Tooltip
          className="cursor-pointer"
          title="Databasus opens an SSH session to the bastion host first, then reaches the database host and port from there."
        >
          <InfoCircleOutlined className="ml-2" style={{ color: 'gray' }} />
        </Tooltip>
      </div>

      {isSshTunnelEnabled && (
        <>
          <div className="mb-1 flex w-full items-center">
            <div className="min-w-[150px]">SSH host</div>
            <Input
              value={sshTunnel.host || ''}
              onChange={(e) => updateSshTunnel({ host: e.target.value.trim() })}
              size="small"
              className="max-w-[200px] grow"
              placeholder="bastion.example.com"
            />
          </div>

          <div className="mb-1 flex w-full items-center">
            <div className="min-w-[150px]">SSH port</div>
            <InputNumber
              min={1}
              max={65535}
              value={sshTunnel.port}
              onChange={(port) => updateSshTunnel({ port: port || DEFAULT_SSH_PORT })}
              size="small"
              className="max-w-[200px] grow"
              placeholder="22"
            />
          </div>

          <div className="mb-1 flex w-full items-center">
            <div className="min-w-[150px]">SSH username</div>
            <Input
              value={sshTunnel.username || ''}
              onChange={(e) => updateSshTunnel({ username: e.target.value.trim() })}
              size="small"
              className="max-w-[200px] grow"
              placeholder="Enter SSH username"
            />
          </div>

          <div className="mb-1 flex w-full items-center">
            <div className="min-w-[150px]">SSH auth method</div>
            <Select
              value={authMethod}
              onChange={changeAuthMethod}
              options={[
                { label: 'Password', value: 'password' },
                { label: 'Private key', value: 'privateKey' },
              ]}
              size="small"
              className="max-w-[200px] grow"
            />
          </div>

          {authMethod === 'password' && (
            <div className="mb-1 flex w-full items-center">
              <div className="min-w-[150px]">SSH password</div>
              <Input.Password
                value={sshTunnel.password || ''}
                onChange={(e) => updateSshTunnel({ password: e.target.value })}
                size="small"
                className="max-w-[200px] grow"
                placeholder="Enter SSH password"
                autoComplete="off"
                data-1p-ignore
                data-lpignore="true"
                data-form-type="other"
              />
            </div>
          )}

          {authMethod === 'privateKey' && (
            <div className="mb-1 flex w-full items-start">
              <div className="min-w-[150px]">SSH private key</div>
              <Input.TextArea
                value={sshTunnel.privateKey || ''}
                onChange={(e) => updateSshTunnel({ privateKey: e.target.value })}
                size="small"
                className="max-w-[300px] grow"
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                autoSize={{ minRows: 2, maxRows: 5 }}
              />
            </div>
          )}

          {authMethod === 'privateKey' && !!sshTunnel.privateKey && (
            <div className="mb-1 flex w-full items-center">
              <div className="min-w-[150px]">Key passphrase</div>
              <Input.Password
                value={sshTunnel.privateKeyPassphrase || ''}
                onChange={(e) => updateSshTunnel({ privateKeyPassphrase: e.target.value })}
                size="small"
                className="max-w-[200px] grow"
                placeholder="Leave empty if the key is not encrypted"
                autoComplete="off"
                data-1p-ignore
                data-lpignore="true"
                data-form-type="other"
              />
            </div>
          )}

          <div className="mb-1 flex w-full items-center">
            <div className="flex min-w-[150px] items-center">
              <span>Skip host key check</span>
              <Tooltip
                className="cursor-pointer"
                title="Accepts any host key presented by the SSH server. This removes the protection against a man in the middle attack - keep it off unless you know why you need it."
              >
                <InfoCircleOutlined className="ml-2" style={{ color: 'gray' }} />
              </Tooltip>
            </div>
            <Checkbox
              checked={sshTunnel.shouldSkipHostKeyCheck || false}
              onChange={(e) => updateSshTunnel({ shouldSkipHostKeyCheck: e.target.checked })}
            />
          </div>

          {!sshTunnel.shouldSkipHostKeyCheck && (
            <div className="mb-1 flex w-full items-center">
              <div className="flex min-w-[150px] items-center">
                <span>Host key fingerprint</span>
                <Tooltip
                  className="cursor-pointer"
                  title="SHA256 fingerprint of the SSH server host key. Get it on the bastion with: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
                >
                  <InfoCircleOutlined className="ml-2" style={{ color: 'gray' }} />
                </Tooltip>
              </div>
              <Input
                value={sshTunnel.hostKeyFingerprint || ''}
                onChange={(e) => updateSshTunnel({ hostKeyFingerprint: e.target.value.trim() })}
                size="small"
                className="max-w-[200px] grow"
                placeholder="SHA256:..."
              />
            </div>
          )}
        </>
      )}
    </div>
  );
};
