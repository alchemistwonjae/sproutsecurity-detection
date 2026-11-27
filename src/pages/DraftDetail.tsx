import { useEffect } from 'react';
import { PageHead } from '../components/ui';
import { Link } from '../lib/router';
import { D, DraftCard, DRAFT_NOTICE } from './Drafts';

export function DraftDetail({ id }: { id: string }) {
  const d = D.find((x) => x.id === id);
  useEffect(() => {
    if (d) document.title = `${d.product} 탐지 룰 초안(검증 전) — Sprout Security Detection Hub`;
  }, [d]);
  if (!d) return <p className="empty">이 초안을 찾을 수 없습니다. <Link to="/drafts">룰 초안 목록으로</Link></p>;
  return (
    <>
      <PageHead title={`${d.product} 탐지 룰 초안`} lead={d.ko.summary} />
      <p className="notice"><strong>{DRAFT_NOTICE.split('. ')[0]}.</strong> {DRAFT_NOTICE.split('. ').slice(1).join('. ')}</p>
      <DraftCard d={d} />
      <p><Link to="/drafts">← 다른 룰 초안 보기</Link></p>
    </>
  );
}
