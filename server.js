require("dotenv").config();
const crypto = require("crypto");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");

const {
  PORT = 3000,
  MAIL_SERVICE_API_KEY,
  FROM_NAME = "ENI Mail",
  FROM_EMAIL,
  BREVO_API_KEY,
  SMTP_HOST,
  SMTP_PORT = "587",
  SMTP_TLS = "true",
  SMTP_USERNAME,
  SMTP_PASSWORD,
} = process.env;

if (!MAIL_SERVICE_API_KEY) {
  console.error("MAIL_SERVICE_API_KEY manquante : arrêt du service.");
  process.exit(1);
}

const log = (level, msg) =>
  console.log(`${new Date().toISOString()} ${level} mail-service: ${msg}`);

const app = express();
app.set("trust proxy", 1); // derrière le proxy Vercel (nécessaire pour le rate limit)
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(rateLimit({ windowMs: 60_000, limit: 60 }));

// ---------- Authentification par clé statique ----------
function requireApiKey(req, res, next) {
  const provided = Buffer.from(String(req.get("x-api-key") || ""));
  const expected = Buffer.from(MAIL_SERVICE_API_KEY);
  // comparaison en temps constant (longueurs égales exigées par timingSafeEqual)
  const ok =
    provided.length === expected.length &&
    crypto.timingSafeEqual(provided, expected);
  if (!ok) return res.status(401).json({ success: false, error: "Clé API invalide" });
  next();
}

// ---------- Canaux d'envoi ----------
async function sendBrevo({ to, subject, html, text }) {
  const resp = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": BREVO_API_KEY,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      sender: { name: FROM_NAME, email: FROM_EMAIL },
      to: [{ email: to }],
      subject,
      htmlContent: html,
      textContent: text,
    }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!resp.ok) {
    const detail = (await resp.text()).slice(0, 300);
    throw new Error(`Brevo HTTP ${resp.status} | ${detail}`);
  }
}

let transporter = null;
if (!BREVO_API_KEY && SMTP_HOST) {
  const port = Number(SMTP_PORT);
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port,
    secure: port === 465, // 465 = SSL implicite
    requireTLS: port !== 465 && SMTP_TLS === "true", // STARTTLS sinon
    auth: SMTP_USERNAME && SMTP_PASSWORD ? { user: SMTP_USERNAME, pass: SMTP_PASSWORD } : undefined,
    connectionTimeout: 20_000,
  });
}

async function sendMail(mail) {
  if (BREVO_API_KEY) {
    await sendBrevo(mail);
    return "brevo";
  }
  if (transporter) {
    await transporter.sendMail({
      from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
      to: mail.to,
      subject: mail.subject,
      html: mail.html,
      text: mail.text,
    });
    return "smtp";
  }
  log("INFO", `Envoi simulé pour ${mail.to} (Sujet: '${mail.subject}'). Aucun canal configuré.`);
  return "simulated";
}

// ---------- Routes ----------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.get("/health", (_req, res) => res.json({ status: "ok" }));

app.post("/send-email", requireApiKey, async (req, res) => {
  const { to, subject, html, text } = req.body || {};

  if (typeof to !== "string" || !EMAIL_RE.test(to))
    return res.status(400).json({ success: false, error: "Champ 'to' invalide" });
  if (typeof subject !== "string" || !subject.trim() || subject.length > 200)
    return res.status(400).json({ success: false, error: "Champ 'subject' invalide" });
  if (!html && !text)
    return res.status(400).json({ success: false, error: "Fournir 'html' et/ou 'text'" });

  try {
    const channel = await sendMail({ to, subject, html, text });
    log("INFO", `E-mail traité pour ${to} via ${channel}`);
    res.json({ success: true, channel });
  } catch (e) {
    // Ne jamais journaliser le contenu (il peut contenir un OTP)
    log("ERROR", `Échec d'envoi pour ${to} : ${e.name}: ${e.message}`);
    res.status(502).json({ success: false, error: "Échec de l'envoi" });
  }
});

// En local : node server.js. Sur Vercel : l'app est exportée et gérée par api/index.js
if (require.main === module) {
  app.listen(PORT, () => log("INFO", `Service démarré sur le port ${PORT}`));
}

module.exports = app;
