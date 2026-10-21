const baseUrl = process.env.INGRESSI_URL;
const token = process.env.INGRESSI_API_TOKEN;
if (!baseUrl || !token) throw new Error("INGRESSI_URL and INGRESSI_API_TOKEN must be set");

export async function ingressi<T>(path: string, init: RequestInit = {}): Promise<T> {
  const url = new URL(path, baseUrl);
  const res = await fetch(url, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...init.headers },
  });
  if (!res.ok) throw new Error(`${init.method ?? "GET"} ${url} failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<T>;
}
