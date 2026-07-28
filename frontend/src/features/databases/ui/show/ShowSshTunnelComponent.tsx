import { type Database, DatabaseType } from '../../../../entity/databases';

interface Props {
  database: Database;
}

export const ShowSshTunnelComponent = ({ database }: Props) => {
  const sshTunnel = database.sshTunnel;

  if (!sshTunnel || database.type === DatabaseType.POSTGRES_PHYSICAL) return null;

  return (
    <div>
      <div className="mb-1 flex w-full items-center">
        <div className="min-w-[150px] break-all">SSH host</div>
        <div>{sshTunnel.host || ''}</div>
      </div>

      <div className="mb-1 flex w-full items-center">
        <div className="min-w-[150px]">SSH port</div>
        <div>{sshTunnel.port || ''}</div>
      </div>

      <div className="mb-1 flex w-full items-center">
        <div className="min-w-[150px]">SSH username</div>
        <div>{sshTunnel.username || ''}</div>
      </div>

      <div className="mb-1 flex w-full items-center">
        <div className="min-w-[150px]">Host key check</div>
        <div>{sshTunnel.shouldSkipHostKeyCheck ? 'Skipped' : 'Enabled'}</div>
      </div>

      {!sshTunnel.shouldSkipHostKeyCheck && !!sshTunnel.hostKeyFingerprint && (
        <div className="mb-1 flex w-full items-center">
          <div className="min-w-[150px]">Host key fingerprint</div>
          <div className="break-all">{sshTunnel.hostKeyFingerprint}</div>
        </div>
      )}
    </div>
  );
};
