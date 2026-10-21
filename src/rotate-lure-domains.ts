import { ingressi } from "./ingressi";

const HOST_ID = 71;
const MAX_DOMAINS = 30;
const ZONE = "kankitsu.space";

type ProxyHost = { id: number; createdAt: string; updatedAt: string; domains: string[] } & Record<string, unknown>;

// Derived from the date so a rerun on the same day adds nothing.
function lureDomain(date: Date) {
  const day = date.toISOString().slice(0, 10);
  const suffix = new Bun.CryptoHasher("sha256").update(`lure:${day}`).digest("hex").slice(0, 8);
  return `vulntest-${suffix}.${ZONE}`;
}

const dryRun = process.argv.includes("--dry-run");
const path = `/api/v1/proxy-hosts/${HOST_ID}`;
const { id, createdAt, updatedAt, ...host } = await ingressi<ProxyHost>(path);

const today = lureDomain(new Date());
// The array is oldest first: new domains are appended, so trimming the front drops the oldest.
const domains = host.domains.includes(today) ? host.domains : [...host.domains, today];
const next = domains.slice(-MAX_DOMAINS);

const added = next.filter((d) => !host.domains.includes(d));
const removed = host.domains.filter((d) => !next.includes(d));
console.log(`added: ${added.join(", ") || "none"}`);
console.log(`removed: ${removed.join(", ") || "none"}`);

if (dryRun || (added.length === 0 && removed.length === 0)) process.exit(0);

await ingressi(path, { method: "PUT", body: JSON.stringify({ ...host, domains: next }) });

// Catches a change held for approval or a reordered domain list.
const saved = await ingressi<ProxyHost>(path);
if (JSON.stringify(saved.domains) !== JSON.stringify(next)) {
  throw new Error(`host ${HOST_ID} domains are ${JSON.stringify(saved.domains)}, expected ${JSON.stringify(next)}`);
}
console.log(`host ${HOST_ID} now has ${next.length} domains`);
