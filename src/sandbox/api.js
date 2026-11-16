// Bekçili sandbox'a istemci API'si (Node ve tarayıcı ortak). Baytlar Uint8Array'dir.
export const PEEL_DEADLINE_MS = 120_000;
export const PING_DEADLINE_MS = 15_000;

export function sandboxApi(send) {
  return {
    ready: async () => {
      const r = await send({ type: 'ping', deadlineMs: PING_DEADLINE_MS });
      if (!r.ok) throw new Error(`sandbox başlatılamadı: ${r.error}`);
      return r;
    },
    /** tam çözme + rapor: { ok, code, java, input, bytes, report, logs, passes, snapshots, ... } */
    peel: (bytes, { name, mapping = null, lang = 'tr', only = null, timeline = true, deadlineMs = PEEL_DEADLINE_MS } = {}) =>
      send({ type: 'peel', bytes, name, mapping, lang, only, timeline, deadlineMs }),
  };
}
