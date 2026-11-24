require("dotenv").config();
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const { Pool } = require("pg");

const app = express();
app.set("trust proxy", 1);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const CPM_RATE = parseFloat(process.env.CPM_RATE || "4.00"); // $4.00 per 1000 completed 4-step views
const MIN_WITHDRAW = parseFloat(process.env.MIN_WITHDRAW || "2.00");

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    store: new pgSession({ pool, tableName: "session" }),
    secret: process.env.SESSION_SECRET || "change-this-super-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

function generateNumericUid() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function generateSlug(len = 6) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  const bytes = crypto.randomBytes(len);
  for (let i = 0; i < len; i++) out += chars[bytes[i] % chars.length];
  return out;
}

function isValidHttpUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// Passport serialization
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const res = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, res.rows[0] || false);
  } catch (err) {
    done(err);
  }
});

// Google OAuth Strategy (enabled automatically when GOOGLE_CLIENT_ID is set)
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${process.env.BASE_URL || ""}/auth/google/callback`,
      },
      async (_accessToken, _refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value?.toLowerCase();
          const googleId = profile.id;
          const name = profile.displayName || "User";
          const avatar = profile.photos?.[0]?.value || null;

          let userRes = await pool.query(
            "SELECT * FROM users WHERE google_id = $1 OR email = $2",
            [googleId, email]
          );

          if (userRes.rowCount > 0) {
            const existing = userRes.rows[0];
            if (!existing.google_id) {
              await pool.query(
                "UPDATE users SET google_id = $1, avatar_url = COALESCE(avatar_url, $2) WHERE id = $3",
                [googleId, avatar, existing.id]
              );
            }
            return done(null, existing);
          }

          const isFirstUser = (await pool.query("SELECT COUNT(*) FROM users")).rows[0].count === "0";
          const role = isFirstUser ? "admin" : "user";
          const inserted = await pool.query(
            `INSERT INTO users (uid, name, email, google_id, avatar_url, role)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [generateNumericUid(), name, email, googleId, avatar, role]
          );
          return done(null, inserted.rows[0]);
        } catch (err) {
          return done(err);
        }
      }
    )
  );
}

function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === "admin") return next();
  res.status(403).send("Admin access required.");
}

// ==================== AUTH ROUTES ====================
app.get("/", (req, res) => {
  if (req.isAuthenticated()) return res.redirect("/dashboard");
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  if (req.isAuthenticated()) return res.redirect("/dashboard");
  res.render("auth", {
    mode: "login",
    error: req.query.error || null,
    googleEnabled: Boolean(process.env.GOOGLE_CLIENT_ID),
  });
});

app.get("/signup", (req, res) => {
  if (req.isAuthenticated()) return res.redirect("/dashboard");
  res.render("auth", {
    mode: "signup",
    error: req.query.error || null,
    googleEnabled: Boolean(process.env.GOOGLE_CLIENT_ID),
  });
});

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 6) {
      return res.redirect("/signup?error=Provide+valid+name,+email,+and+6%2B+char+password");
    }
    const cleanEmail = email.trim().toLowerCase();
    const exists = await pool.query("SELECT id FROM users WHERE email = $1", [cleanEmail]);
    if (exists.rowCount > 0) {
      return res.redirect("/signup?error=Email+already+registered");
    }

    const hash = await bcrypt.hash(password, 10);
    const isFirstUser = (await pool.query("SELECT COUNT(*) FROM users")).rows[0].count === "0";
    const role = isFirstUser ? "admin" : "user";

    const inserted = await pool.query(
      `INSERT INTO users (uid, name, email, password_hash, role)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [generateNumericUid(), name.trim(), cleanEmail, hash, role]
    );

    req.login(inserted.rows[0], (err) => {
      if (err) return res.redirect("/login");
      res.redirect("/dashboard");
    });
  } catch (err) {
    console.error(err);
    res.redirect("/signup?error=Registration+failed");
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = (email || "").trim().toLowerCase();
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [cleanEmail]);
    if (userRes.rowCount === 0 || !userRes.rows[0].password_hash) {
      return res.redirect("/login?error=Invalid+email+or+password");
    }
    const user = userRes.rows[0];
    const ok = await bcrypt.compare(password || "", user.password_hash);
    if (!ok) return res.redirect("/login?error=Invalid+email+or+password");

    req.login(user, (err) => {
      if (err) return res.redirect("/login?error=Session+error");
      res.redirect("/dashboard");
    });
  } catch (err) {
    console.error(err);
    res.redirect("/login?error=Login+failed");
  }
});

app.get("/auth/google", (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID) return res.redirect("/login?error=Google+OAuth+not+configured");
  passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
});

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login?error=Google+login+failed" }),
  (_req, res) => res.redirect("/dashboard")
);

app.post("/logout", (req, res) => {
  req.logout(() => res.redirect("/login"));
});

// ==================== USER DASHBOARD ROUTES ====================
app.get("/dashboard", ensureAuth, async (req, res) => {
  const tab = req.query.tab || "overview";
  const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get("host")}`;

  const [linksRes, withdrawRes, ticketsRes] = await Promise.all([
    pool.query("SELECT * FROM shortlinks WHERE user_id = $1 ORDER BY created_at DESC", [req.user.id]),
    pool.query("SELECT * FROM withdrawals WHERE user_id = $1 ORDER BY created_at DESC", [req.user.id]),
    pool.query("SELECT * FROM support_tickets WHERE user_id = $1 ORDER BY created_at DESC", [req.user.id]),
  ]);

  const totals = linksRes.rows.reduce(
    (acc, l) => {
      acc.clicks += l.clicks;
      acc.views += l.completed_views;
      acc.earned += parseFloat(l.earned);
      return acc;
    },
    { clicks: 0, views: 0, earned: 0 }
  );

  res.render("dashboard", {
    user: req.user,
    tab,
    baseUrl,
    links: linksRes.rows,
    withdrawals: withdrawRes.rows,
    tickets: ticketsRes.rows,
    totals,
    cpmRate: CPM_RATE,
    minWithdraw: MIN_WITHDRAW,
    msg: req.query.msg || null,
    err: req.query.err || null,
  });
});

app.post("/links/create", ensureAuth, async (req, res) => {
  try {
    const { destination_url, title, custom_slug } = req.body;
    if (!isValidHttpUrl(destination_url)) {
      return res.redirect("/dashboard?tab=links&err=Invalid+destination+URL+(must+start+with+http/https)");
    }

    let slug = (custom_slug || "").trim().replace(/[^a-zA-Z0-9_-]/g, "");
    if (!slug) slug = generateSlug(6);

    const dup = await pool.query("SELECT id FROM shortlinks WHERE slug = $1", [slug]);
    if (dup.rowCount > 0) {
      return res.redirect("/dashboard?tab=links&err=Alias+already+taken,+try+another");
    }

    await pool.query(
      "INSERT INTO shortlinks (user_id, slug, title, destination_url) VALUES ($1, $2, $3, $4)",
      [req.user.id, slug, (title || "").trim().slice(0, 180), destination_url.trim()]
    );

    res.redirect("/dashboard?tab=links&msg=Shortlink+created+successfully");
  } catch (err) {
    console.error(err);
    res.redirect("/dashboard?tab=links&err=Could+not+create+shortlink");
  }
});

app.post("/links/delete/:id", ensureAuth, async (req, res) => {
  await pool.query("DELETE FROM shortlinks WHERE id = $1 AND user_id = $2", [
    req.params.id,
    req.user.id,
  ]);
  res.redirect("/dashboard?tab=links&msg=Shortlink+deleted");
});

app.post("/withdraw", ensureAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const amount = parseFloat(req.body.amount);
    const method = (req.body.method || req.user.payout_method || "").trim();
    const address = (req.body.address || req.user.payout_address || "").trim();

    if (isNaN(amount) || amount < MIN_WITHDRAW) {
      return res.redirect(`/dashboard?tab=withdraw&err=Minimum+withdrawal+is+$${MIN_WITHDRAW.toFixed(2)}`);
    }
    if (!address) {
      return res.redirect("/dashboard?tab=withdraw&err=Please+enter+a+valid+wallet+or+UPI+address");
    }

    await client.query("BEGIN");
    const uRes = await client.query("SELECT balance FROM users WHERE id = $1 FOR UPDATE", [req.user.id]);
    const currentBal = parseFloat(uRes.rows[0].balance);

    if (amount > currentBal) {
      await client.query("ROLLBACK");
      return res.redirect("/dashboard?tab=withdraw&err=Insufficient+balance");
    }

    await client.query("UPDATE users SET balance = balance - $1 WHERE id = $2", [amount, req.user.id]);
    await client.query(
      "INSERT INTO withdrawals (user_id, amount, method, address) VALUES ($1, $2, $3, $4)",
      [req.user.id, amount, method, address]
    );
    await client.query("COMMIT");

    res.redirect("/dashboard?tab=withdraw&msg=Withdrawal+request+submitted");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.redirect("/dashboard?tab=withdraw&err=Withdrawal+failed");
  } finally {
    client.release();
  }
});

app.post("/profile/update", ensureAuth, async (req, res) => {
  const { name, payout_method, payout_address } = req.body;
  await pool.query(
    "UPDATE users SET name = $1, payout_method = $2, payout_address = $3 WHERE id = $4",
    [(name || req.user.name).trim(), payout_method, (payout_address || "").trim(), req.user.id]
  );
  res.redirect("/dashboard?tab=profile&msg=Profile+updated");
});

app.post("/support/create", ensureAuth, async (req, res) => {
  const { subject, message } = req.body;
  if (!subject || !message) {
    return res.redirect("/dashboard?tab=support&err=Subject+and+message+are+required");
  }
  await pool.query("INSERT INTO support_tickets (user_id, subject, message) VALUES ($1, $2, $3)", [
    req.user.id,
    subject.trim().slice(0, 200),
    message.trim(),
  ]);
  res.redirect("/dashboard?tab=support&msg=Support+ticket+submitted");
});

// ==================== 4-STEP ROTATING ARTICLE GATEWAY ====================
app.get("/s/:slug", async (req, res) => {
  try {
    const { slug } = req.params;
    const linkRes = await pool.query("SELECT * FROM shortlinks WHERE slug = $1 AND active = TRUE", [slug]);
    if (linkRes.rowCount === 0) return res.status(404).send("Shortlink not found or inactive.");
    const link = linkRes.rows[0];

    const cookieName = `gw_${slug}`;
    let gwToken = req.cookies[cookieName];
    let sess = null;

    if (gwToken && /^[a-f0-9]{64}$/.test(gwToken)) {
      const sRes = await pool.query(
        "SELECT * FROM gateway_sessions WHERE session_token = $1 AND slug = $2",
        [gwToken, slug]
      );
      if (sRes.rowCount > 0) sess = sRes.rows[0];
    }

    if (!sess) {
      gwToken = crypto.randomBytes(32).toString("hex");
      res.cookie(cookieName, gwToken, {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: 6 * 60 * 60 * 1000,
      });
      await pool.query("UPDATE shortlinks SET clicks = clicks + 1 WHERE id = $1", [link.id]);
      const ins = await pool.query(
        `INSERT INTO gateway_sessions (session_token, slug, visitor_ip, completed_steps, required_steps)
         VALUES ($1, $2, $3, 0, 4) RETURNING *`,
        [gwToken, slug, req.ip]
      );
      sess = ins.rows[0];
    }

    // 5TH TIME (after 4 completed article loops) -> credit earnings & open actual destination URL
    if (sess.completed_steps >= sess.required_steps) {
      await pool.query("DELETE FROM gateway_sessions WHERE session_token = $1", [gwToken]);
      res.clearCookie(cookieName);

      const payoutPerView = CPM_RATE / 1000;
      await pool.query(
        "UPDATE shortlinks SET completed_views = completed_views + 1, earned = earned + $1 WHERE id = $2",
        [payoutPerView, link.id]
      );
      await pool.query("UPDATE users SET balance = balance + $1 WHERE id = $2", [
        payoutPerView,
        link.user_id,
      ]);

      return res.redirect(302, link.destination_url);
    }

    // Pick a random active article (excluding the immediately preceding one)
    let artRes = await pool.query(
      `SELECT * FROM articles
       WHERE active = TRUE AND ($1::text IS NULL OR url <> $1)
       ORDER BY RANDOM() LIMIT 1`,
      [sess.current_article_url]
    );
    if (artRes.rowCount === 0) {
      artRes = await pool.query("SELECT * FROM articles WHERE active = TRUE ORDER BY RANDOM() LIMIT 1");
    }
    if (artRes.rowCount === 0) {
      return res.status(500).send("No rotating articles configured by admin yet.");
    }

    const article = artRes.rows[0];
    const waitSeconds = Math.floor(Math.random() * 6) + 15; // Random 15 to 20 seconds
    const stepToken = crypto.randomBytes(24).toString("hex");

    await pool.query(
      `UPDATE gateway_sessions
       SET current_article_url = $1,
           step_token = $2,
           wait_seconds = $3,
           step_started_at = NOW(),
           updated_at = NOW()
       WHERE session_token = $4`,
      [article.url, stepToken, waitSeconds, gwToken]
    );

    res.render("gateway", {
      slug,
      stepNumber: sess.completed_steps + 1,
      totalSteps: sess.required_steps,
      waitSeconds,
      stepToken,
      article,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Gateway error");
  }
});

// Server-side anti-skip step verification endpoint
app.post("/s/:slug/verify", async (req, res) => {
  try {
    const { slug } = req.params;
    const { step_token } = req.body;
    const gwToken = req.cookies[`gw_${slug}`];

    if (!gwToken || !step_token) {
      return res.status(400).json({ ok: false, error: "Invalid session token." });
    }

    const sRes = await pool.query(
      "SELECT * FROM gateway_sessions WHERE session_token = $1 AND slug = $2",
      [gwToken, slug]
    );
    if (sRes.rowCount === 0) {
      return res.status(404).json({ ok: false, error: "Session expired." });
    }

    const sess = sRes.rows[0];
    if (sess.step_token !== step_token || !sess.step_started_at) {
      return res.status(403).json({ ok: false, error: "Step token mismatch (skip attempt blocked)." });
    }

    const elapsed = (Date.now() - new Date(sess.step_started_at).getTime()) / 1000;
    if (elapsed < sess.wait_seconds - 1) {
      return res.status(429).json({
        ok: false,
        error: `Timer not finished (${Math.ceil(sess.wait_seconds - elapsed)}s left).`,
      });
    }

    // Consume step_token (single-use) and increment completed_steps
    await pool.query(
      `UPDATE gateway_sessions
       SET completed_steps = completed_steps + 1,
           step_token = NULL,
           step_started_at = NULL,
           updated_at = NOW()
       WHERE session_token = $1`,
      [gwToken]
    );

    return res.json({ ok: true, nextUrl: `/s/${encodeURIComponent(slug)}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Verification error" });
  }
});

// ==================== ADMIN ROUTES ====================
app.get("/admin", ensureAdmin, async (_req, res) => {
  const [articles, withdrawals, tickets, stats] = await Promise.all([
    pool.query("SELECT * FROM articles ORDER BY id DESC"),
    pool.query(
      `SELECT w.*, u.email, u.uid FROM withdrawals w
       JOIN users u ON u.id = w.user_id ORDER BY w.created_at DESC`
    ),
    pool.query(
      `SELECT t.*, u.email, u.uid FROM support_tickets t
       JOIN users u ON u.id = t.user_id ORDER BY t.created_at DESC`
    ),
    pool.query(
      `SELECT
        (SELECT COUNT(*) FROM users) AS total_users,
        (SELECT COUNT(*) FROM shortlinks) AS total_links,
        (SELECT COALESCE(SUM(completed_views), 0) FROM shortlinks) AS total_views`
    ),
  ]);

  res.render("admin", {
    articles: articles.rows,
    withdrawals: withdrawals.rows,
    tickets: tickets.rows,
    stats: stats.rows[0],
  });
});

app.post("/admin/articles/add", ensureAdmin, async (req, res) => {
  const { title, url } = req.body;
  if (isValidHttpUrl(url)) {
    await pool.query(
      "INSERT INTO articles (title, url) VALUES ($1, $2) ON CONFLICT (url) DO UPDATE SET title = $1, active = TRUE",
      [(title || "Article").trim(), url.trim()]
    );
  }
  res.redirect("/admin");
});

app.post("/admin/articles/delete/:id", ensureAdmin, async (req, res) => {
  await pool.query("DELETE FROM articles WHERE id = $1", [req.params.id]);
  res.redirect("/admin");
});

app.post("/admin/withdrawals/:id/:action", ensureAdmin, async (req, res) => {
  const { id, action } = req.params;
  if (action === "approve") {
    await pool.query("UPDATE withdrawals SET status = 'approved' WHERE id = $1", [id]);
  } else if (action === "reject") {
    const wRes = await pool.query("SELECT * FROM withdrawals WHERE id = $1 AND status = 'pending'", [id]);
    if (wRes.rowCount > 0) {
      await pool.query("UPDATE users SET balance = balance + $1 WHERE id = $2", [
        wRes.rows[0].amount,
        wRes.rows[0].user_id,
      ]);
      await pool.query("UPDATE withdrawals SET status = 'rejected' WHERE id = $1", [id]);
    }
  }
  res.redirect("/admin");
});

app.post("/admin/tickets/:id/reply", ensureAdmin, async (req, res) => {
  await pool.query("UPDATE support_tickets SET admin_reply = $1, status = 'answered' WHERE id = $2", [
    (req.body.reply || "").trim(),
    req.params.id,
  ]);
  res.redirect("/admin");
});

app.get("/health", (_req, res) => res.status(200).send("OK"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MBS Shortlink running on port ${PORT}`));