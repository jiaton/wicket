/**
 * A prefix check on the raw path (`/.well-known/acme-challenge/`, `bypass`, `passthrough.paths`)
 * must not be defeated by segments the origin may collapse: `..%2f..%2fadmin` keeps the
 * prefix as text while some servers resolve it to `/admin`. Such paths get no special
 * treatment and fall through to the normal gate.
 */
export function hasTraversal(pathname: string): boolean {
  if (/%2f|%5c|\\/i.test(pathname)) return true;
  let decoded = pathname;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return true;
  }
  return decoded.split('/').some((seg) => seg === '..' || seg === '.');
}

/** True when `pathname` is under `prefix` and carries no traversal tricks. */
export const underPrefix = (pathname: string, prefix: string): boolean => pathname.startsWith(prefix) && !hasTraversal(pathname);
