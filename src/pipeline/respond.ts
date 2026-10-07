/** Tiny response constructors shared by the pipeline steps; never cached. */
export const html = (body: string, status: number, extra: Record<string, string> = {}): Response =>
  new Response(body, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...extra },
  });

export const json = (body: unknown, status: number): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
