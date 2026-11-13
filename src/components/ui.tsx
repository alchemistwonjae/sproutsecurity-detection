import { Link } from '../lib/router';
import { levelKo, statusKo, tacticKo } from '../lib/labels';

export const LevelBadge = ({ level }: { level: string }) => <span className={`badge lv-${level}`}>{levelKo(level)}</span>;
export const StatusBadge = ({ status }: { status: string }) => <span className={`badge st-${status}`}>{statusKo(status)}</span>;
export const KevBadge = () => <span className="badge kev" title="CISA KEV: 실제 악용이 확인된 취약점">실제 악용(KEV)</span>;

export const CveChip = ({ id, kev }: { id: string; kev?: boolean }) => (
  <Link to={`/cves/${id}`} className={`chip${kev ? ' chip-kev' : ''}`} title={kev ? '실제 악용 확인(KEV)' : undefined}>
    {id}
    {kev ? ' ●' : ''}
  </Link>
);

export const TacticChip = ({ t }: { t: string }) => (
  <Link to={`/rules?tactic=${t}`} className="chip chip-soft" title={t}>
    {tacticKo(t)}
  </Link>
);

export const Loading = ({ error }: { error?: boolean }) =>
  error ? (
    <p className="empty">데이터를 불러오지 못했습니다. <code>npm run collect</code>로 데이터를 먼저 만들었는지 확인하세요.</p>
  ) : (
    <p className="empty">불러오는 중…</p>
  );

export const PageHead = ({ title, lead }: { title: string; lead?: string }) => (
  <header className="page-head">
    <h1>{title}</h1>
    {lead && <p className="lead">{lead}</p>}
  </header>
);
