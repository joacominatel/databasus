import {
  type Database,
  getDatabaseLogoFromType,
  getDatabaseTypeLabel,
} from '../../../../entity/databases';
import { ShowSshTunnelComponent } from './ShowSshTunnelComponent';

interface Props {
  database: Database;
  isShowName?: boolean;
  isShowType?: boolean;
}

export const ShowDatabaseBaseInfoComponent = ({ database, isShowName, isShowType }: Props) => {
  return (
    <div>
      {isShowName && (
        <div className="mb-1 flex w-full items-center">
          <div className="min-w-[150px]">Name</div>
          <div>{database.name || ''}</div>
        </div>
      )}

      {isShowType && (
        <div className="mb-1 flex w-full items-center">
          <div className="min-w-[150px]">Database type</div>
          <div className="flex items-center">
            <span>{getDatabaseTypeLabel(database.type)}</span>
            <img
              src={getDatabaseLogoFromType(database.type)}
              alt="databaseIcon"
              className="ml-2 h-4 w-4"
            />
          </div>
        </div>
      )}

      <ShowSshTunnelComponent database={database} />
    </div>
  );
};
