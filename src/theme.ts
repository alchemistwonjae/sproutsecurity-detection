export type Theme = 'auto' | 'light' | 'dark';

export const readTheme = (): Theme => {
  try {
    const t = localStorage.getItem('theme');
    return t === 'light' || t === 'dark' ? t : 'auto';
  } catch {
    return 'auto';
  }
};

export const applyTheme = (t: Theme) => {
  const el = document.documentElement;
  if (t === 'auto') delete el.dataset.theme;
  else el.dataset.theme = t;
  try {
    if (t === 'auto') localStorage.removeItem('theme');
    else localStorage.setItem('theme', t);
  } catch {
    /* 저장 불가 환경에서는 이번 방문에만 적용 */
  }
};
