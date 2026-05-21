// Initializes the Postgres schema. Run with: DATABASE_URL=... node scripts/migrate.js
const { findOne } = require("../api/_lib/db");

(async () => {
  if (!process.env.DATABASE_URL) {
    console.log("DATABASE_URL not set. The file-based fallback initializes lazily; no migration needed.");
    return;
  }
  // findOne triggers pgClient() which runs migrations
  await findOne("users", { id: "__noop__" });
  console.log("Schema is up to date.");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
