import { useEffect, useState, type AnchorHTMLAttributes } from 'react';

export function navigate(to: string, replace = false) {
  if (replace) history.replaceState(null, '', to);
  else history.pushState(null, '', to);
  window.dispatchEvent(new Event('navchange'));
}

export function useLocation(): { path: string; search: string } {
  const read = () => ({ path: location.pathname, search: location.search });
  const [loc, setLoc] = useState(read);
  useEffect(() => {
    const on = () => setLoc(read());
    addEventListener('popstate', on);
    addEventListener('navchange', on);
    return () => {
      removeEventListener('popstate', on);
      removeEventListener('navchange', on);
    };
  }, []);
  return loc;
}

export function Link({ to, onClick, ...rest }: { to: string } & AnchorHTMLAttributes<HTMLAnchorElement>) {
  return (
    <a
      href={to}
      onClick={(e) => {
        onClick?.(e);
        if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
        e.preventDefault();
        navigate(to);
        window.scrollTo(0, 0);
      }}
      {...rest}
    />
  );
}
