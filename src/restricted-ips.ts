import { BlockList } from "node:net";
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

// Requests that reach Ingressi through another proxy show its private address,
// and blocking that would block legitimate traffic too.
const PRIVATE = new BlockList();
for (const [net, prefix] of [["10.0.0.0", 8], ["172.16.0.0", 12], ["192.168.0.0", 16], ["127.0.0.0", 8], ["100.64.0.0", 10], ["169.254.0.0", 16]] as const) {
  PRIVATE.addSubnet(net, prefix, "ipv4");
}
for (const [net, prefix] of [["fc00::", 7], ["fe80::", 10], ["::1", 128]] as const) {
  PRIVATE.addSubnet(net, prefix, "ipv6");
}
const isPrivate = (ip: string) => PRIVATE.check(ip, ip.includes(":") ? "ipv6" : "ipv4");

type WafEvent = { id: string | null; clientIp: string; countryCode: string | null; ruleId: number | null; blocked: boolean };
type WafEventsPage = { events: WafEvent[]; total: number };
type RequestRow = { asn: number; asOrg: string };
type Source = { country: string | null; requests: number; asn?: number; asOrg?: string };

// Pin the window so new events don't shift pages while we read them.
const to = Math.floor(Date.now() / 1000);
const from = to - WINDOW_SECONDS;

function fetchPage(page: number) {
  const query = new URLSearchParams({ page: `${page}`, perPage: `${PER_PAGE}`, from: `${from}`, to: `${to}` });
  return ingressi<WafEventsPage>(`/api/v1/waf/events?${query}`);
}

// WAF events carry no ASN, so take it from the newest logged request from that IP.
async function lookupAsn(ip: string) {
  const filters = JSON.stringify([{ dim: "ip", value: ip }, { dim: "asn", op: "is_not", value: "0" }]);
  const query = new URLSearchParams({ range: "custom", from: `${from}`, to: `${to}`, limit: "1", filters });
  const { requests } = await ingressi<{ requests: RequestRow[] }>(`/api/v1/analytics/requests?${query}`);
  return requests[0];
}

const sources = new Map<string, Source>();
// A request that matches several rules produces one event per rule.
const countedRequests = new Set<string>();
let scanned = 0;
for (let page = 1; ; page++) {
  const { events, total } = await fetchPage(page);
  for (const e of events) {
    if (!e.blocked || e.ruleId === null || !RULES.has(e.ruleId) || isPrivate(e.clientIp)) continue;
    const source = sources.get(e.clientIp) ?? { country: e.countryCode, requests: 0 };
    sources.set(e.clientIp, source);
    if (e.id !== null && countedRequests.has(e.id)) continue;
    if (e.id !== null) countedRequests.add(e.id);
    source.requests++;
  }
  scanned += events.length;
  if (events.length < PER_PAGE || scanned >= total) break;
}

const entries = [...sources];
for (let i = 0; i < entries.length; i += 10) {
  await Promise.all(
    entries.slice(i, i + 10).map(async ([ip, source]) => {
      const row = await lookupAsn(ip);
      if (row) Object.assign(source, { asn: row.asn, asOrg: row.asOrg });
    }),
  );
}

const sorted = [...sources.keys()].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
await Bun.write("restricted-ips.txt", sorted.join("\n") + "\n");

function tally(key: (s: Source) => string) {
  const groups = new Map<string, { ips: number; requests: number }>();
  for (const s of sources.values()) {
    const group = groups.get(key(s)) ?? { ips: 0, requests: 0 };
    groups.set(key(s), group);
    group.ips++;
    group.requests += s.requests;
  }
  return [...groups].sort(([, a], [, b]) => b.ips - a.ips || b.requests - a.requests);
}

const countryNames = new Intl.DisplayNames(["en"], { type: "region" });
const countryLabel = (code: string | null) => (code ? `${countryNames.of(code)} (${code})` : "Unknown");
const asnLabel = (s: Source) => (s.asn ? `AS${s.asn} ${s.asOrg}` : "Unknown");
const totalRequests = [...sources.values()].reduce((sum, s) => sum + s.requests, 0);

const markdown = `# Mitigated IPs

Requests blocked by restricted file and path WAF rules in the last 30 days: ${sources.size} IPs, ${totalRequests} requests.

## By country

| Country | IPs | Requests |
| --- | ---: | ---: |
${tally((s) => countryLabel(s.country)).map(([label, g]) => `| ${label} | ${g.ips} | ${g.requests} |`).join("\n")}

## By ASN

| ASN | IPs | Requests |
| --- | ---: | ---: |
${tally(asnLabel).map(([label, g]) => `| ${label} | ${g.ips} | ${g.requests} |`).join("\n")}
`;
await Bun.write("analytics.md", markdown);

console.log(`Scanned ${scanned} events, wrote ${sorted.length} IPs to restricted-ips.txt and analytics.md`);
