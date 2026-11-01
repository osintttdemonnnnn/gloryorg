"use client";

import { useCallback, useMemo, useState } from "react";

type Severity = "critical" | "high" | "medium" | "low" | "clear";

type BreachRecord = {
  id: string;
  source: string;
  sourceUrl?: string;
  matchedField: "discord_id" | "username" | "email" | "fivem_license" | "phone";
  matchedValue: string;
  breachName: string;
  breachDate?: string;
  publishedAt?: string;
  dataClasses: string[];
  recordCount?: number;
  confidence: number;
  verified?: boolean;
  notes?: string;
};

type ScanResponse = {
  discordId: string;
  scannedAt: string;
  records: BreachRecord[];
  sourcesQueried: string[];
  errors?: string[];
};

const DISCORD_ID_RE = /^\d{17,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const FIVEM_RE = /^[a-f0-9]{32}$/i;

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "border-red-500/50 bg-red-500/10 text-red-300",
  high: "border-orange-500/50 bg-orange-500/10 text-orange-300",
  medium: "border-amber-500/50 bg-amber-500/10 text-amber-300",
  low: "border-sky-500/50 bg-sky-500/10 text-sky-300",
  clear: "border-emerald-500/50 bg-emerald-500/10 text-emerald-300",
};

function getSeverity(records: BreachRecord[]): Severity {
  if (!records.length) return "clear";

  const dangerous = ["password", "password_hash", "steam", "session", "cookie", "ip_address"];
  const hasCritical = records.some((record) =>
    record.dataClasses.some((item) => dangerous.includes(item.toLowerCase()))
  );

  if (hasCritical || records.length >= 10) return "critical";
  if (records.length >= 4) return "high";
  if (records.length >= 1) return "medium";
  return "clear";
}

function formatDate(value?: string) {
  if (!value) return "Unknown";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function maskValue(value: string) {
  if (value.includes("@")) {
    const [user, domain] = value.split("@");
    return `${user.slice(0, 2)}${"*".repeat(Math.max(user.length - 2, 2))}@${domain}`;
  }

  if (value.length > 10) {
    return `${value.slice(0, 4)}${"*".repeat(value.length - 8)}${value.slice(-4)}`;
  }

  return value;
}

export default function IndexPage() {
  const [discordId, setDiscordId] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [fivemLicense, setFivemLicense] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canScan = useMemo(() => {
    if (!DISCORD_ID_RE.test(discordId.trim())) return false;
    if (email && !EMAIL_RE.test(email.trim())) return false;
    if (fivemLicense && !FIVEM_RE.test(fivemLicense.trim())) return false;
    return true;
  }, [discordId, email, fivemLicense]);

  const runScan = useCallback(async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch("/api/breach-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          discordId: discordId.trim(),
          username: username.trim() || undefined,
          email: email.trim() || undefined,
          fivemLicense: fivemLicense.trim() || undefined,
        }),
      });

      const data = await response.json();

      if (!response.ok) throw new Error(data.error ?? "Breach scan failed");

      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unexpected error");
    } finally {
      setLoading(false);
    }
  }, [discordId, username, email, fivemLicense]);

  const severity = getSeverity(result?.records ?? []);
  const uniqueSources = new Set(result?.records.map((record) => record.source) ?? []);

  return (
    <main className="min-h-screen bg-[#05070c] p-4 text-slate-200 md:p-8">
      <div className="mx-auto max-w-6xl">
        <header className="mb-6 rounded-xl border border-cyan-500/20 bg-gradient-to-r from-[#071018] to-[#050a12] p-5 shadow-[0_0_40px_rgba(6,182,212,0.08)]">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h1 className="font-mono text-2xl font-bold tracking-widest text-cyan-300">
                BREACH INTELLIGENCE
              </h1>
              <p className="mt-1 text-sm text-slate-400">
                Discord identity exposure assessment · indexed leak records only
              </p>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-1 text-cyan-300">
                LIVE SCAN
              </span>
              <span className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-slate-400">
                AUDIT ENABLED
              </span>
            </div>
          </div>
        </header>

        <section className="mb-6 rounded-xl border border-slate-800 bg-[#070b12] p-5">
          <div className="grid gap-4 md:grid-cols-2">
            <Field label="DISCORD ID" placeholder="123456789012345678" value={discordId} onChange={setDiscordId} required />
            <Field label="DISCORD USERNAME" placeholder="optional" value={username} onChange={setUsername} />
            <Field label="EMAIL" placeholder="optional · authorized use only" value={email} onChange={setEmail} />
            <Field label="FIVEM LICENSE" placeholder="optional · 32-character license" value={fivemLicense} onChange={setFivemLicense} />
          </div>

          <div className="mt-5 flex flex-wrap items-center gap-3">
            <button
              onClick={runScan}
              disabled={!canScan || loading}
              className="rounded-md border border-cyan-400/40 bg-cyan-500/10 px-5 py-2 font-mono text-sm font-semibold tracking-wider text-cyan-200 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {loading ? "SCANNING…" : "RUN BREACH SCAN"}
            </button>

            <p className="text-xs text-slate-500">
              Results indicate whether identifiers appear in indexed breach or leak datasets. They are not conclusive proof of account compromise.
            </p>
          </div>

          {error && (
            <div className="mt-4 rounded-md border border-red-500/40 bg-red-500/10 p-3 font-mono text-sm text-red-300">
              ERROR: {error}
            </div>
          )}
        </section>

        {result && (
          <section className="space-y-6">
            <div className="rounded-xl border border-slate-800 bg-[#070b12] p-5">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <h2 className="font-mono text-lg tracking-widest text-slate-100">TARGET DOSSIER</h2>
                <span className={`rounded-md border px-3 py-1 font-mono text-xs font-bold uppercase tracking-widest ${SEVERITY_STYLES[severity]}`}>
                  {severity === "clear" ? "NO INDEXED HITS" : `${severity} exposure`}
                </span>
              </div>

              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <Stat label="TARGET ID" value={result.discordId} mono />
                <Stat label="INDEXED RECORDS" value={String(result.records.length)} />
                <Stat label="SOURCES HIT" value={String(uniqueSources.size)} />
                <Stat label="SCAN TIME" value={formatDate(result.scannedAt)} />
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                {result.sourcesQueried.map((source) => (
                  <span key={source} className="rounded border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-[11px] text-slate-400">
                    {source}
                  </span>
                ))}
              </div>
            </div>

            {result.records.length === 0 ? (
              <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-6 text-center">
                <p className="font-mono text-emerald-300">NO INDEXED BREACH RECORDS FOUND</p>
                <p className="mt-2 text-sm text-slate-400">
                  No matching records were returned by the enabled sources for the supplied identifiers.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {result.records.map((record) => (
                  <article key={record.id} className="rounded-xl border border-slate-800 bg-[#070b12] p-5 transition hover:border-cyan-500/30">
                    <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <h3 className="font-mono text-base font-bold text-slate-100">{record.breachName}</h3>
                        <p className="mt-1 text-xs text-slate-500">
                          Source: {record.source}
                          {record.sourceUrl && (
                            <>
                              {" · "}
                              <a href={record.sourceUrl} target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline">
                                open source
                              </a>
                            </>
                          )}
                        </p>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-[11px] text-slate-300">
                          {record.matchedField.toUpperCase()}
                        </span>
                        <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-1 font-mono text-[11px] text-cyan-300">
                          {record.confidence}% CONFIDENCE
                        </span>
                        {record.verified && (
                          <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 font-mono text-[11px] text-emerald-300">
                            VERIFIED
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                      <Stat label="MATCHED VALUE" value={maskValue(record.matchedValue)} mono />
                      <Stat label="BREACH DATE" value={formatDate(record.breachDate)} />
                      <Stat label="PUBLISHED" value={formatDate(record.publishedAt)} />
                      <Stat label="RECORD COUNT" value={record.recordCount?.toLocaleString() ?? "Unknown"} />
                    </div>

                    {record.dataClasses.length > 0 && (
                      <div className="mt-4">
                        <p className="mb-2 font-mono text-[11px] tracking-widest text-slate-500">EXPOSED DATA CLASSES</p>
                        <div className="flex flex-wrap gap-2">
                          {record.dataClasses.map((item) => (
                            <span key={item} className="rounded border border-red-500/30 bg-red-500/10 px-2 py-1 font-mono text-[11px] text-red-300">
                              {item}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {record.notes && (
                      <p className="mt-4 rounded-md border border-slate-800 bg-slate-900/60 p-3 text-sm text-slate-400">{record.notes}</p>
                    )}
                  </article>
                ))}
              </div>
            )}

            <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-sm text-amber-200/80">
              <strong className="font-mono tracking-wider">OPERATIONAL NOTICE:</strong>{" "}
              Use only for authorized security research, account-self checks, or lawful moderation. Do not expose credentials, full personal data, or use results to harass, dox, or target individuals.
            </div>
          </section>
        )}
      </div>
    </main>
  );
}

function Field({ label, placeholder, value, onChange, required }: {
  label: string;
  placeholder: string;
  value: string;
  onChange: (value: string) => void;
  required?: boolean;
}) {
  return (
    <label className="block">
      <span className="mb-1 block font-mono text-[11px] tracking-widest text-slate-500">
        {label}
        {required && <span className="text-red-400"> *</span>}
      </span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="w-full rounded-md border border-slate-800 bg-[#04070d] px-3 py-2 font-mono text-sm text-slate-200 outline-none transition placeholder:text-slate-600 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30"
      />
    </label>
  );
}

function Stat({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-[#04070d] p-3">
      <p className="font-mono text-[10px] tracking-widest text-slate-500">{label}</p>
      <p className={`mt-1 break-all text-sm text-slate-100 ${mono ? "font-mono" : ""}`}>{value}</p>
    </div>
  );
}
