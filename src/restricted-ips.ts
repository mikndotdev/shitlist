import { ingressi } from "./ingressi";

const RULES = new Map([
  [930100, "Path Traversal Attack"],
  [930120, "OS File Access Attempt"],
  [930130, "Restricted File Access Attempt"],
  [930140, "Restricted File Access Attempt: AI Coding Assistant Artifact"],
  [920440, "URL file extension is restricted by policy"],
  [920500, "Attempt to access a backup or working file"],
]);

const PER_PAGE = 200;
const WINDOW_SECONDS = 30 * 24 * 60 * 60;

type WafEvent = { clientIp: string; ruleId: number | null; blocked: boolean };
type WafEventsPage = { events: WafEvent[]; total: number };

const outFile = process.argv[2] ?? "restricted-ips.txt";
// Pin the window so new events don't shift pages while we read them.
const to = Math.floor(Date.now() / 1000);
const from = to - WINDOW_SECONDS;

function fetchPage(page: number) {
  const query = new URLSearchParams({ page: `${page}`, perPage: `${PER_PAGE}`, from: `${from}`, to: `${to}` });
  return ingressi<WafEventsPage>(`/api/v1/waf/events?${query}`);
}

const ips = new Set<string>();
let scanned = 0;
for (let page = 1; ; page++) {
  const { events, total } = await fetchPage(page);
  for (const e of events) {
    if (e.blocked && e.ruleId !== null && RULES.has(e.ruleId)) ips.add(e.clientIp);
  }
  scanned += events.length;
  if (events.length < PER_PAGE || scanned >= total) break;
}

const sorted = [...ips].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
await Bun.write(outFile, sorted.join("\n") + "\n");
console.log(`Scanned ${scanned} events, wrote ${sorted.length} IPs to ${outFile}`);
