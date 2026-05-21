const nodemailer = require("nodemailer");

function isConfigured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

let transporter = null;
function getTransporter() {
  if (!isConfigured()) return null;
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }
  return transporter;
}

async function sendReportEmail({ to, subject, text, html, attachments }) {
  const mailer = getTransporter();
  if (!mailer) {
    const error = new Error("Email delivery is not configured. Set SMTP_HOST/SMTP_USER/SMTP_PASS.");
    error.statusCode = 501;
    error.code = "email_not_configured";
    throw error;
  }
  return mailer.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject,
    text,
    html,
    attachments
  });
}

module.exports = { isConfigured, sendReportEmail };
