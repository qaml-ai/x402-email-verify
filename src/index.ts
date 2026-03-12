import { Hono } from "hono";
import { cdpPaymentMiddleware } from "x402-cdp";
import { describeRoute, openAPIRouteHandler } from "hono-openapi";

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

// OpenAPI spec — must be before paymentMiddleware
app.get("/.well-known/openapi.json", openAPIRouteHandler(app, {
  documentation: {
    info: {
      title: "x402 Email Verification Service",
      description: "Verify if an email address is valid and likely deliverable. Checks format, DNS, MX records, disposable domains. Pay-per-use via x402 protocol on Base mainnet.",
      version: "1.0.0",
    },
    servers: [{ url: "https://verify.camelai.io" }],
  },
}));

// --- x402 payment gate ---
app.use(
  cdpPaymentMiddleware(
    (env) => ({
      "GET /verify": {
        accepts: [
          {
            scheme: "exact",
            price: "$0.005",
            network: "eip155:8453",
            payTo: env.SERVER_ADDRESS as `0x${string}`,
          },
        ],
        description: "Verify if an email address is valid and likely deliverable",
        mimeType: "application/json",
        extensions: {
          bazaar: {
            discoverable: true,
            inputSchema: {
              queryFields: {
                email: {
                  type: "string",
                  description: "Email address to verify",
                  required: true,
                },
              },
            },
          },
        },
      },
    })
  )
);

// --- Verification endpoint ---
app.get("/verify", describeRoute({
  description: "Verify if an email address is valid and likely deliverable. Requires x402 payment ($0.005).",
  responses: {
    200: { description: "Email verification result", content: { "application/json": { schema: { type: "object" } } } },
    400: { description: "Missing email parameter" },
    402: { description: "Payment required" },
  },
}), async (c) => {
  const email = c.req.query("email");

  if (!email) {
    return c.json({ error: "Missing 'email' query parameter" }, 400);
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

export default app;
