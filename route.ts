import { NextResponse } from "next/server";

const DISCORD_ID_RE = /^\d{17,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const FIVEM_RE = /^[a-f0-9]{32}$/i;

type Identifier = {
  field: "discord_id" | "username" | "email" | "fivem_license";
  value: string;
};

export async function POST(request: Request) {
  const body = await request.json();
  const discordId = String(body.discordId ?? "").trim();

  if (!DISCORD_ID_RE.test(discordId)) {
    return NextResponse.json({ error: "Invalid Discord ID" }, { status: 400 });
  }

  const email = body.email ? String(body.email).trim() : undefined;
  const username = body.username ? String(body.username).trim() : undefined;
  const fivemLicense = body.fivemLicense ? String(body.fivemLicense).trim() : undefined;

  if (email && !EMAIL_RE.test(email)) {
    return NextResponse.json({ error: "Invalid email" }, { status: 400 });
  }

  if (fivemLicense && !FIVEM_RE.test(fivemLicense)) {
    return NextResponse.json({ error: "Invalid FiveM license" }, { status: 400 });
  }

  const identifiers: Identifier[] = [
    { field: "discord_id", value: discordId },
    { field: "discord_id", value: `discord:${discordId}` },
  ];

  if (username) identifiers.push({ field: "username", value: username });
  if (email) identifiers.push({ field: "email", value: email });
  if (fivemLicense) identifiers.push({ field: "fivem_license", value: fivemLicense });

  const records = [];
  const errors: string[] = [];

  for (const identifier of identifiers) {
    try {
      const providerRecords = await queryProviders(identifier);
      records.push(...providerRecords);
    } catch (err) {
      errors.push(
        `${identifier.field}:${identifier.value} — ${err instanceof Error ? err.message : "provider error"}`
      );
    }
  }

  const unique = Array.from(new Map(records.map((record) => [record.id, record])).values());

  return NextResponse.json({
    discordId,
    scannedAt: new Date().toISOString(),
    records: unique,
    sourcesQueried: ["your_breach_provider", "fivem_breach_provider", "hibp"],
    errors,
  });
}

async function queryProviders(identifier: Identifier) {
  const results = await Promise.allSettled([
    queryGenericBreachProvider(identifier),
    queryFiveMProvider(identifier),
    identifier.field === "email" ? queryHibp(identifier.value) : Promise.resolve([]),
  ]);

  const records = [];

  for (const result of results) {
    if (result.status === "fulfilled") records.push(...result.value);
  }

  return records;
}

async function queryGenericBreachProvider(identifier: Identifier) {
  if (!process.env.BREACH_API_BASE || !process.env.BREACH_API_KEY) return [];

  const res = await fetch(
    `${process.env.BREACH_API_BASE}/search?q=${encodeURIComponent(identifier.value)}`,
    {
      headers: {
        Authorization: `Bearer ${process.env.BREACH_API_KEY}`,
        Accept: "application/json",
      },
    }
  );

  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`Breach provider returned ${res.status}`);

  const data = await res.json();

  return (data.results ?? []).map((item: any, index: number) => ({
    id: `${identifier.field}:${identifier.value}:${item.breach ?? item.source}:${index}`,
    source: item.source ?? "your_breach_provider",
    sourceUrl: item.url,
    matchedField: identifier.field,
    matchedValue: identifier.value,
    breachName: item.breach ?? item.database ?? "Unattributed leak",
    breachDate: item.date ?? item.breach_date,
    publishedAt: item.published_at,
    dataClasses: item.fields ?? item.data_classes ?? [],
    recordCount: item.record_count,
    confidence: item.confidence ?? 70,
    verified: item.verified ?? false,
    notes: item.notes,
  }));
}

async function queryFiveMProvider(identifier: Identifier) {
  if (!process.env.FIVEM_BREACH_API_BASE || !process.env.FIVEM_BREACH_API_KEY) return [];

  const res = await fetch(
    `${process.env.FIVEM_BREACH_API_BASE}/search?q=${encodeURIComponent(identifier.value)}`,
    {
      headers: {
        Authorization: `Bearer ${process.env.FIVEM_BREACH_API_KEY}`,
        Accept: "application/json",
      },
    }
  );

  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`FiveM provider returned ${res.status}`);

  const data = await res.json();

  return (data.results ?? []).map((item: any, index: number) => ({
    id: `fivem:${identifier.value}:${item.breach ?? item.source}:${index}`,
    source: item.source ?? "fivem_breach_provider",
    sourceUrl: item.url,
    matchedField: identifier.field,
    matchedValue: identifier.value,
    breachName: item.breach ?? item.database ?? "FiveM leak",
    breachDate: item.date,
    publishedAt: item.published_at,
    dataClasses: item.fields ?? [],
    recordCount: item.record_count,
    confidence: item.confidence ?? 65,
    verified: item.verified ?? false,
    notes: item.notes,
  }));
}

async function queryHibp(email: string) {
  if (!process.env.HIBP_API_KEY) return [];

  const res = await fetch(
    `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
    {
      headers: {
        "hibp-api-key": process.env.HIBP_API_KEY,
        "user-agent": "DiscordBreachScanner",
      },
    }
  );

  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`HIBP returned ${res.status}`);

  const data = await res.json();

  return data.map((item: any) => ({
    id: `hibp:${email}:${item.Name}`,
    source: "Have I Been Pwned",
    sourceUrl: `https://haveibeenpwned.com/breach/${item.Name}`,
    matchedField: "email",
    matchedValue: email,
    breachName: item.Name,
    breachDate: item.BreachDate,
    publishedAt: item.AddedDate,
    dataClasses: item.DataClasses ?? [],
    recordCount: item.PwnCount,
    confidence: 95,
    verified: true,
    notes: item.Description?.replace(/<[^>]+>/g, ""),
  }));
}
