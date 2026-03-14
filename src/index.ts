import { Hono } from "hono";
import { cdpPaymentMiddleware } from "x402-cdp";
import { extractParams } from "x402-ai";
import { openapiFromMiddleware } from "x402-openapi";

const app = new Hono<{ Bindings: Env }>();

// --- Disposable email domains (~50 common ones) ---
const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com",
  "guerrillamail.com",
  "guerrillamail.de",
  "tempmail.com",
  "throwaway.email",
  "temp-mail.org",
  "fakeinbox.com",
  "sharklasers.com",
  "guerrillamailblock.com",
  "grr.la",
  "dispostable.com",
  "yopmail.com",
  "trashmail.com",
  "trashmail.me",
  "trashmail.net",
  "mailnesia.com",
  "maildrop.cc",
  "discard.email",
  "mailcatch.com",
  "tempail.com",
  "harakirimail.com",
  "jetable.org",
  "spamgourmet.com",
  "mytemp.email",
  "getairmail.com",
  "getnada.com",
  "mailsac.com",
  "burnermail.io",
  "inboxbear.com",
  "mailnull.com",
  "spamfree24.org",
  "trash-mail.com",
  "tempr.email",
  "10minutemail.com",
  "10minutemail.net",
  "mohmal.com",
  "tempinbox.com",
  "emailondeck.com",
  "crazymailing.com",
  "tmail.ws",
  "mailtemp.net",
  "tempmailo.com",
  "mintemail.com",
  "instantemailaddress.com",
  "throwam.com",
  "filzmail.com",
  "mailexpire.com",
  "tempomail.fr",
  "fuglu.com",
  "guerrillamail.net",
]);

// --- Free email providers ---
const FREE_PROVIDERS = new Set([
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "yahoo.co.uk",
  "yahoo.co.jp",
  "yahoo.fr",
  "yahoo.de",
  "hotmail.com",
  "hotmail.co.uk",
  "outlook.com",
  "outlook.fr",
  "live.com",
  "live.co.uk",
  "msn.com",
  "aol.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "protonmail.com",
  "proton.me",
  "zoho.com",
  "mail.com",
  "gmx.com",
  "gmx.de",
  "gmx.net",
  "yandex.com",
  "yandex.ru",
  "fastmail.com",
  "tutanota.com",
  "tuta.io",
  "inbox.com",
  "mail.ru",
]);

// --- Email format validation ---
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

interface MxRecord {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DnsResponse {
  Status: number;
  Answer?: MxRecord[];
}

async function lookupMxRecords(domain: string): Promise<string[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`;
  const res = await fetch(url, {
    headers: { Accept: "application/dns-json" },
  });

  if (!res.ok) return [];

  const data: DnsResponse = await res.json();
  if (data.Status !== 0 || !data.Answer) return [];

  return data.Answer
    .filter((r) => r.type === 15) // MX record type
    .sort((a, b) => {
      // MX data format: "priority hostname" — sort by priority
      const pa = parseInt(a.data.split(" ")[0], 10) || 0;
      const pb = parseInt(b.data.split(" ")[0], 10) || 0;
      return pa - pb;
    })
    .map((r) => {
      // Extract hostname from "priority hostname"
      const parts = r.data.split(" ");
      const host = parts.length > 1 ? parts[1] : parts[0];
      return host.replace(/\.$/, ""); // strip trailing dot
    });
}

async function domainExists(domain: string): Promise<boolean> {
  // Check for any DNS record (A, AAAA, or MX) to confirm domain exists
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`;
  const res = await fetch(url, {
    headers: { Accept: "application/dns-json" },
  });
  if (!res.ok) return false;
  const data: DnsResponse = await res.json();
  // Status 0 = NOERROR (domain exists), 3 = NXDOMAIN (doesn't exist)
  return data.Status === 0;
}

function determineVerdict(
  validFormat: boolean,
  domainOk: boolean,
  hasMx: boolean,
  isDisposable: boolean
): "deliverable" | "undeliverable" | "risky" {
  if (!validFormat || !domainOk) return "undeliverable";
  if (!hasMx) return "undeliverable";
  if (isDisposable) return "risky";
  return "deliverable";
}

const SYSTEM_PROMPT = `You are a parameter extractor for an email verification service.
Extract the following from the user's message and return JSON:
- "email": the email address to verify (required)

Return ONLY valid JSON, no explanation.
Examples:
- {"email": "user@example.com"}
- {"email": "test@gmail.com"}`;

const ROUTES = {
  "POST /": {
    accepts: [{ scheme: "exact", price: "$0.005", network: "eip155:8453", payTo: "0x0" as `0x${string}` }],
    description: "Verify if an email address is valid and likely deliverable. Send {\"input\": \"your request\"}",
    mimeType: "application/json",
    extensions: {
      bazaar: {
        info: {
          input: {
            type: "http",
            method: "POST",
            bodyType: "json",
            body: {
              input: { type: "string", description: "Provide the email address to verify", required: true },
            },
          },
          output: { type: "json" },
        },
        schema: {
          properties: {
            input: {
              properties: { method: { type: "string", enum: ["POST"] } },
              required: ["method"],
            },
          },
        },
      },
    },
  },
};

app.use(
  cdpPaymentMiddleware((env) => ({
    "POST /": { ...ROUTES["POST /"], accepts: [{ ...ROUTES["POST /"].accepts[0], payTo: env.SERVER_ADDRESS as `0x${string}` }] },
  }))
);

app.post("/", async (c) => {
  const body = await c.req.json<{ input?: string }>();
  if (!body?.input) {
    return c.json({ error: "Missing 'input' field" }, 400);
  }

  const params = await extractParams(c.env.CF_GATEWAY_TOKEN, SYSTEM_PROMPT, body.input);
  const email = params.email as string;
  if (!email) {
    return c.json({ error: "Could not determine email address to verify" }, 400);
  }

  const validFormat = EMAIL_REGEX.test(email);
  const domain = email.split("@")[1]?.toLowerCase() || "";

  if (!validFormat || !domain) {
    return c.json({
      email,
      valid_format: false,
      domain_exists: false,
      has_mx_records: false,
      mx_records: [],
      is_disposable: false,
      is_free_provider: false,
      verdict: "undeliverable",
    });
  }

  // Run DNS lookups in parallel
  const [domainOk, mxRecords] = await Promise.all([
    domainExists(domain),
    lookupMxRecords(domain),
  ]);

  const hasMx = mxRecords.length > 0;
  const isDisposable = DISPOSABLE_DOMAINS.has(domain);
  const isFreeProvider = FREE_PROVIDERS.has(domain);
  const verdict = determineVerdict(validFormat, domainOk, hasMx, isDisposable);

  return c.json({
    email,
    valid_format: validFormat,
    domain_exists: domainOk,
    has_mx_records: hasMx,
    mx_records: mxRecords,
    is_disposable: isDisposable,
    is_free_provider: isFreeProvider,
    verdict,
  });
});

app.get("/.well-known/openapi.json", openapiFromMiddleware("x402 Email Verify", "verify.camelai.io", ROUTES));

app.get("/", (c) => {
  return c.json({
    service: "x402-email-verify",
    description: "Verify if an email address is valid and likely deliverable. Send POST / with {\"input\": \"verify user@example.com\"}",
    price: "$0.005 per request (Base mainnet)",
  });
});

export default app;
