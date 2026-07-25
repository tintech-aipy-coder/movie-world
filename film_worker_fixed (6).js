// Movie Search Telegram Bot — Cloudflare Worker
// Single-file, zero deps. TMDB API for movies/series, DDG-style scrape for subtitles.

const TMDB_API = "https://api.themoviedb.org/3";
// ONE source of truth so it's impossible to leak a token client-side.
const TMDB_KEY_ENV = "TMDB_KEY";
const BOT_TOKEN = "BOT_TOKEN";
// Secret Telegram echoes back on every real webhook push (set via
// /setup-webhook, verified on every /webhook request below). Without this,
// anyone who discovers the worker's URL could POST forged Telegram updates
// (fake messages, fake callback taps, fake web_app_data) straight to
// handleUpdate as if they came from Telegram itself.
const WEBHOOK_SECRET_ENV = "WEBHOOK_SECRET";
// Separate secret gating the manual/admin-only browser endpoints
// (/setup-webhook, /webhook-info, /trigger-daily) so a stranger who finds
// the worker's hostname can't re-point the webhook or mass-push notifications.
const ADMIN_SECRET_ENV = "ADMIN_SECRET";
const POSTER_BASE = "https://image.tmdb.org/t/p/w500";

// Constant-time string compare — a plain `===` on secrets leaks timing
// information an attacker can use to guess the secret byte-by-byte.
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  if (ea.length !== eb.length) {
    // Still walk a fixed-size buffer so the comparison time doesn't leak
    // the real secret's length either.
    let dummy = 0;
    for (let i = 0; i < ea.length; i++) dummy |= ea[i];
    return false;
  }
  let diff = 0;
  for (let i = 0; i < ea.length; i++) diff |= ea[i] ^ eb[i];
  return diff === 0;
}

// Requires env.ADMIN_SECRET to be set as a Wrangler secret and passed as
// ?key=... on manual endpoints. If ADMIN_SECRET hasn't been configured yet,
// access is allowed through (so the very first /setup-webhook call after a
// fresh deploy still works) — but this should be set immediately in
// production: `wrangler secret put ADMIN_SECRET`.
function isAdminAuthorized(request, env, url) {
  const configured = env[ADMIN_SECRET_ENV];
  if (!configured) return true;
  const supplied = url.searchParams.get("key") || request.headers.get("X-Admin-Key") || "";
  return timingSafeEqual(supplied, configured);
}

// Validates Telegram's WebApp `initData` per Telegram's own documented
// algorithm (HMAC-SHA256, key derived from the bot token) and returns the
// authenticated Telegram user object, or null if the data is missing,
// malformed, stale, or its signature doesn't match. This is the ONLY
// trustworthy source of "who is making this request" for the Mini App API —
// a `uid` value taken straight from a query string or POST body can be set
// to anyone's id by anyone, so it must never be trusted on its own.
async function verifyTelegramInitData(initData, botToken) {
  if (!initData || !botToken) return null;
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    if (!hash) return null;
    params.delete("hash");
    const pairs = [];
    for (const [k, v] of params.entries()) pairs.push(`${k}=${v}`);
    pairs.sort();
    const dataCheckString = pairs.join("\n");

    const enc = new TextEncoder();
    const webAppDataKey = await crypto.subtle.importKey(
      "raw", enc.encode("WebAppData"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const secretKeyBuf = await crypto.subtle.sign("HMAC", webAppDataKey, enc.encode(botToken));
    const secretKey = await crypto.subtle.importKey(
      "raw", secretKeyBuf, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const sigBuf = await crypto.subtle.sign("HMAC", secretKey, enc.encode(dataCheckString));
    const computedHash = [...new Uint8Array(sigBuf)].map((b) => b.toString(16).padStart(2, "0")).join("");

    if (!timingSafeEqual(computedHash, hash)) return null;

    // Reject stale sessions — a captured/replayed initData string shouldn't
    // work forever. Telegram Mini Apps re-issue this on every open.
    const authDate = Number(params.get("auth_date") || 0);
    if (!authDate || (Date.now() / 1000 - authDate) > 86400) return null;

    const userRaw = params.get("user");
    const user = userRaw ? JSON.parse(userRaw) : null;
    if (!user?.id) return null;
    return user;
  } catch {
    return null;
  }
}

// ---------- TMDB helpers ----------

async function tmdb(env, path, params = {}) {
  const key = env[TMDB_KEY_ENV];
  if (!key) return { ok: false, error: "TMDB_KEY missing" };
  const qs = new URLSearchParams({ api_key: key, ...params }).toString();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const resp = await fetch(`${TMDB_API}${path}?${qs}`, { signal: controller.signal });
    if (!resp.ok) {
      let detail = "";
      try { detail = (await resp.json())?.status_message || ""; } catch {}
      return { ok: false, error: `TMDB ${resp.status}${detail ? `: ${detail}` : ""}` };
    }
    return { ok: true, data: await resp.json() };
  } catch (e) {
    // Network error, timeout/abort, or bad JSON — never let this bubble up
    // as an uncaught exception (that would 500 the whole Worker response).
    return { ok: false, error: e?.name === "AbortError" ? "TMDB timeout" : `TMDB fetch failed: ${e?.message || e}` };
  } finally {
    clearTimeout(timer);
  }
}

// Fetches a movie-list endpoint and a tv-list endpoint in parallel, tags
// each raw TMDB result with media_type, and interleaves them into one list.
// Used both by the bot's menu actions (raw results → detailsKeyboard) and
// by the Mini App API (raw results → mapItem).
async function mixedList(env, moviePath, tvPath, movieParams, tvParams, limit = 12) {
  const [rm, rt] = await Promise.all([
    tmdb(env, moviePath, movieParams),
    tmdb(env, tvPath, tvParams),
  ]);
  const m = (rm.ok ? rm.data.results : []).map((x) => ({ ...x, media_type: "movie" }));
  const t = (rt.ok ? rt.data.results : []).map((x) => ({ ...x, media_type: "tv" }));
  const merged = [];
  const max = Math.max(m.length, t.length);
  for (let i = 0; i < max; i++) {
    if (m[i]) merged.push(m[i]);
    if (t[i]) merged.push(t[i]);
  }
  return merged.slice(0, limit);
}

// Same idea as mixedList, but pages through each TMDB endpoint (instead of
// only ever reading page 1) so it can actually satisfy a full 50-item list.
// Used by the Mini App's "مشاهده همه" (view all) full-list pages.
async function mixedListFull(env, moviePath, tvPath, movieParams, tvParams, limit = 50) {
  const pagesNeeded = Math.ceil(limit / 20) + 1;
  const scan = async (path, params, type) => {
    const out = [];
    for (let page = 1; page <= pagesNeeded; page++) {
      const r = await tmdb(env, path, { ...params, page: String(page) });
      if (!r.ok || !r.data.results?.length) break;
      out.push(...r.data.results.map((x) => ({ ...x, media_type: type })));
      if (page >= (r.data.total_pages || 1)) break;
    }
    return out;
  };
  const [m, t] = await Promise.all([
    scan(moviePath, movieParams, "movie"),
    scan(tvPath, tvParams, "tv"),
  ]);
  const merged = [];
  const max = Math.max(m.length, t.length);
  for (let i = 0; i < max; i++) {
    if (m[i]) merged.push(m[i]);
    if (t[i]) merged.push(t[i]);
  }
  return merged.slice(0, limit);
}

// Full (50-item) versions of the home-screen categories, for the Mini App's
// "مشاهده همه" pages. "top" and "trending" mirror the two halves of
// emitSuggestions but paged out to 50 instead of capped at 5.
async function fetchFullList(env, kind, limit = 50) {
  if (kind === "top") {
    const pagesNeeded = Math.ceil(limit / 20) + 1;
    const scan = async (path, params, type) => {
      const out = [];
      for (let page = 1; page <= pagesNeeded; page++) {
        const r = await tmdb(env, path, { ...params, page: String(page) });
        if (!r.ok || !r.data.results?.length) break;
        out.push(...r.data.results.map((x) => ({ ...x, media_type: type })));
        if (page >= (r.data.total_pages || 1)) break;
      }
      return out;
    };
    const [m, t] = await Promise.all([
      scan("/discover/movie", { sort_by: "vote_average.desc", "vote_count.gte": "1000" }, "movie"),
      scan("/discover/tv", { sort_by: "vote_average.desc", "vote_count.gte": "300" }, "tv"),
    ]);
    return m.concat(t).sort((x, y) => (y.vote_average || 0) - (x.vote_average || 0)).slice(0, limit);
  }
  if (kind === "popular") {
    return mixedListFull(env, "/movie/popular", "/tv/popular", { page: "1" }, { page: "1" }, limit);
  }
  if (kind === "now_playing") {
    return mixedListFull(env, "/movie/now_playing", "/tv/on_the_air", { page: "1" }, { page: "1" }, limit);
  }
  if (kind === "upcoming") {
    const today = new Date().toISOString().slice(0, 10);
    return mixedListFull(env, "/movie/upcoming", "/discover/tv",
      { page: "1" },
      { page: "1", sort_by: "first_air_date.desc", "first_air_date.gte": today },
      limit);
  }
  return [];
}

function fmtMovies(results, label) {
  // results: [{ id, title, poster_path, release_date, vote_average }]
  if (!results || results.length === 0) return "نتیجه‌ای پیدا نشد.";
  const lines = results.slice(0, 10).map((m, i) => {
    const yr = (m.release_date || m.first_air_date || "").slice(0, 4);
    const rating = m.vote_average ? ` ⭐${m.vote_average.toFixed(1)}` : "";
    return `${i + 1}. ${m.title || m.name} (${yr})${rating}`;
  });
  return `🎬 ${label}\n\n${lines.join("\n")}\n\nبرای دیدن جزئیات، روی عدد فیلم پاسخ دهید.`;
}

function detailsKeyboard(results) {
  return {
    reply_markup: {
      inline_keyboard: results.slice(0, 10).map((m, i) => {
        const type = m.media_type || m.type || "movie";
        const icon = type === "tv" ? "📺" : "🎬";
        return [{
          text: `${icon} ${i + 1}. ${(m.title || m.name).slice(0, 36)}`,
          callback_data: `m:${type}:${m.id}`,
        }];
      }),
    },
  };
}

// Compact shape shared by the chat bot and the Mini App JSON API.
// `type` is "movie" or "tv" — always pass it explicitly when known (TMDB's
// own media_type field is only present on /search/multi and /trending/*
// results, not on /discover or /movie|tv/popular etc).
function mapItem(m, type) {
  return {
    id: m.id,
    type: type || m.media_type || "movie",
    title: m.title || m.name || "",
    year: (m.release_date || m.first_air_date || "").slice(0, 4),
    rating: m.vote_average ? Number(m.vote_average.toFixed(1)) : null,
    poster: m.poster_path ? `${POSTER_BASE}${m.poster_path}` : null,
    overview: m.overview || "",
  };
}

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("");

function buildAlphabetRows(gid) {
  const rows = [];
  for (let i = 0; i < ALPHABET.length; i += 6) {
    rows.push(ALPHABET.slice(i, i + 6).map((l) => ({ text: l, callback_data: `gl:${gid}:${l}` })));
  }
  rows.push([{ text: "🔙  بازگشت", callback_data: "menu:genres" }]);
  return rows;
}

// Persian genre names read far better in the UI than the English default,
// and TMDB's own genre-list translations are reliably complete (unlike
// per-movie overviews, which are translated only for a subset of titles).
// Movie and TV genre ids don't share a namespace (e.g. "Action" is 28 for
// movies but part of 10759 "Action & Adventure" for TV), so genres are
// merged by Persian name into a composite id "movieId|tvId" (either half
// can be empty). Browsing that genre later queries whichever half exists.
// Static list of the most common/well-known genres, mapped to TMDB's own
// (stable, documented) genre ids — no network call needed, so this can
// never fail the way the old TMDB /genre/list fetch could. Composite id
// is "movieId|tvId" (either half can be empty), same convention used by
// findMoviesByGenreLetter below.
const GENRES = [
  { name: "اکشن", movieId: 28, tvId: 10759 },
  { name: "ماجراجویی", movieId: 12, tvId: 10759 },
  { name: "انیمیشن", movieId: 16, tvId: 16 },
  { name: "کمدی", movieId: 35, tvId: 35 },
  { name: "جنایی", movieId: 80, tvId: 80 },
  { name: "مستند", movieId: 99, tvId: 99 },
  { name: "درام", movieId: 18, tvId: 18 },
  { name: "خانوادگی", movieId: 10751, tvId: 10751 },
  { name: "فانتزی", movieId: 14, tvId: 10765 },
  { name: "تاریخی", movieId: 36, tvId: null },
  { name: "ترسناک", movieId: 27, tvId: null },
  { name: "موزیکال", movieId: 10402, tvId: null },
  { name: "معمایی", movieId: 9648, tvId: 9648 },
  { name: "عاشقانه", movieId: 10749, tvId: null },
  { name: "علمی-تخیلی", movieId: 878, tvId: 10765 },
  { name: "جنگی", movieId: 10752, tvId: 10768 },
  { name: "وسترن", movieId: 37, tvId: 37 },
];

async function getGenres(env) {
  const genres = GENRES.map((g) => ({ id: `${g.movieId || ""}|${g.tvId || ""}`, name: g.name }));
  return { ok: true, genres };
}

// Discover doesn't support "title starts with", so we page through the
// genre sorted by popularity and filter client-side until we have enough
// matches (or run out of pages worth checking). Movie and TV halves of the
// composite genre id are scanned in parallel and merged.
async function findMoviesByGenreLetter(env, gidComposite, letter) {
  const [movieGid, tvGid] = String(gidComposite).split("|");
  const matches = [];
  const scan = async (path, gid, type) => {
    if (!gid) return;
    for (let page = 1; page <= 8 && matches.length < 20; page++) {
      const r = await tmdb(env, path, { with_genres: gid, sort_by: "popularity.desc", page: String(page) });
      if (!r.ok || !r.data.results?.length) break;
      for (const m of r.data.results) {
        const title = (m.title || m.name || "").trim();
        if (title.toUpperCase().startsWith(letter)) matches.push({ ...m, media_type: type });
      }
      if (page >= (r.data.total_pages || 1)) break;
    }
  };
  await Promise.all([scan("/discover/movie", movieGid, "movie"), scan("/discover/tv", tvGid, "tv")]);
  return matches.slice(0, 10);
}

// ponytail: m2m100 quality is mediocre; Gemini/DeepL on free tier is worth it
// once out of free quota — entity-safe 4-byte Persian often gets mojibake. Add
// provider config in KV when fallback quality matters.
// Translates text → Persian via Workers AI. Single attempt with 3s timeout;
// falls back to original English on miss.
async function toFa(env, text) {
  if (!text) return text;
  if (!env.AI) return text;
  try {
    const r = await Promise.race([
      env.AI.run("@cf/meta/m2m100-1.2b",
        { text, source_lang: "en", target_lang: "fa" }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 3000)),
    ]);
    return r?.translated_text || text;
  } catch { return text; }
}

// ---------- Movie/series details ----------

async function getFullDetails(id, env, type = "movie") {
  if (type === "tv") {
    const [base, credits] = await Promise.all([
      tmdb(env, `/tv/${id}`, { append_to_response: "external_ids,videos" }),
      tmdb(env, `/tv/${id}/credits`),
    ]);
    if (!base.ok) return null;
    const d = base.data;
    const c = credits.ok ? credits.data : {};
    // TV has no "director" credit — created_by (showrunners) fills the same UI slot.
    const directors = (d.created_by || []).map((x) => x.name).join(", ");
    const cast = (c.cast || []).slice(0, 5).map((x) => x.name).join(", ");
    const genres = (d.genres || []).map((g) => g.name).join(", ");
    return {
      id: d.id,
      type: "tv",
      title: d.name,
      year: (d.first_air_date || "").slice(0, 4),
      rating: d.vote_average?.toFixed(1),
      votes: d.vote_count,
      runtime: (d.episode_run_time && d.episode_run_time[0]) || null,
      seasons: d.number_of_seasons || null,
      episodes: d.number_of_episodes || null,
      overview: d.overview,
      genres,
      directors,
      cast,
      poster: d.poster_path ? `${POSTER_BASE}${d.poster_path}` : null,
      imdb: d.external_ids?.imdb_id || null,
    };
  }
  const [base, credits] = await Promise.all([
    tmdb(env, `/movie/${id}`, { append_to_response: "external_ids,videos" }),
    tmdb(env, `/movie/${id}/credits`),
  ]);
  if (!base.ok) return null;
  const d = base.data;
  const c = credits.ok ? credits.data : {};
  const directors = (c.crew || []).filter((x) => x.job === "Director").map((x) => x.name).join(", ");
  const cast = (c.cast || []).slice(0, 5).map((x) => x.name).join(", ");
  const genres = (d.genres || []).map((g) => g.name).join(", ");
  return {
    id: d.id,
    type: "movie",
    title: d.title,
    year: (d.release_date || "").slice(0, 4),
    rating: d.vote_average?.toFixed(1),
    votes: d.vote_count,
    runtime: d.runtime,
    overview: d.overview,
    genres,
    directors,
    cast,
    poster: d.poster_path ? `${POSTER_BASE}${d.poster_path}` : null,
    imdb: d.external_ids?.imdb_id || null,
  };
}

// ponytail: parallel translate with 3s timeout; falls back to English on miss.
// m2m100 quality is mediocre for proper nouns (names will transliterate or stay);
// acceptable for overview / genres. Switch to Gemini when free-tier quota matters.
async function dFa(env, d) {
  if (!env.AI) return d;
  const [title, genres, directors, cast, overview] = await Promise.all([
    toFa(env, d.title), toFa(env, d.genres), toFa(env, d.directors),
    toFa(env, d.cast),   toFa(env, d.overview),
  ]);
  return { ...d, title, genres, directors, cast, overview };
}

function fmtDetails(d) {
  const isTv = d.type === "tv";
  const lines = [
    `${isTv ? "📺" : "🎬"} <b>${escape(d.title)}</b> (${d.year || "—"})`,
    `⭐ <b>امتیاز TMDB:</b> ${d.rating || "—"}/10 (${d.votes || 0} رای)`,
    isTv
      ? `📅 ${d.seasons ? `${d.seasons} فصل` : "?"}${d.episodes ? ` · ${d.episodes} قسمت` : ""}`
      : `⏱ مدت: ${d.runtime || "?"} دقیقه`,
    `🎭 ژانر: ${d.genres || "—"}`,
    isTv ? `🎥 سازنده: ${d.directors || "—"}` : `🎥 کارگردان: ${d.directors || "—"}`,
    `👥 بازیگران: ${d.cast || "—"}`,
  ];
  if (d.imdb) lines.push(`🔗 IMDB: https://www.imdb.com/title/${d.imdb}`);
  if (d.overview) lines.push(`\n📖 ${escape(d.overview)}`);
  lines.push(`\n📦 <a href="https://filmo.ir">filmo.ir</a>\n📦 <a href="https://subf2m.co">subf2m.co</a>`);
  lines.push(`<i>برای دانلود این فیلم/سریال می‌توانید از طریق این دو سایت اقدام کنید</i>`);
  return lines.join("\n");
}

// ---------- Subtitle search (lightweight scrape) ----------

async function findSubtitles(title, year) {
  // Two parallel searches: subtitlecat.com + filmo.ir
  // filmo.ir is a movie-post catalog (WP-JSON), not a subtitle bytes host —
  // we return its post URLs as Persian-subtitle landing pages.
  const headers = { "User-Agent": "Mozilla/5.0 (compatible; MovieBot/1.0)" };
  // NOTE: `cf: { timeout }` is not a real Cloudflare fetch option — it was
  // silently ignored, so a slow/unresponsive scrape target had no actual
  // time limit and could stall the whole movie-detail response. AbortController
  // enforces a real 5s cutoff per site instead.
  const fetchWithTimeout = (url, ms = 5000) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ms);
    return fetch(url, { headers, signal: controller.signal }).finally(() => clearTimeout(timer));
  };
  const [cat, filmo] = await Promise.all([
    fetchWithTimeout(`https://www.subtitlecat.com/index.php?search=${encodeURIComponent(`${title} ${year || ""} persian`)}`)
      .then(r => r.ok ? r.text() : "").catch(() => ""),
    fetchWithTimeout(`https://filmo.ir/wp-json/wp/v2/posts?search=${encodeURIComponent(title)}&per_page=5`)
      .then(r => r.ok ? r.json() : []).catch(() => []),
  ]);

  const catLinks = [];
  if (cat) {
    const rx = /href="(\/index\.php\?subtitle=[^"]+)"/g;
    let m;
    while ((m = rx.exec(cat)) && catLinks.length < 3) catLinks.push(`https://www.subtitlecat.com${m[1]}`);
  }

  const filmoLinks = (Array.isArray(filmo) ? filmo : []).map(p => p.link).filter(Boolean);
  return { catLinks, filmoLinks };
}

function fmtSubtitleLinks({ catLinks, filmoLinks }) {
  const lines = [];
  if (filmoLinks.length) {
    lines.push(`🇮🇷 <b>filmo.ir</b> (صفحه فیلم + زیرنویس فارسی):`);
    filmoLinks.slice(0, 5).forEach((u, i) => lines.push(`${i + 1}. ${u}`));
  }
  if (catLinks.length) {
    lines.push(`\n🔤 <b>Subtitlecat</b>:`);
    catLinks.slice(0, 3).forEach((u, i) => lines.push(`${i + 1}. ${u}`));
  }
  if (!lines.length) {
    return "📥 زیرنویس فارسی پیدا نشد. در <b>filmo.ir</b> یا <b>subf2m.co</b> جستجو کن.";
  }
  return `📥 <b>لینک‌های زیرنویس فارسی</b>\n━━━━━━━━━━\n\n${lines.join("\n")}`;
}

// ---------- Telegram plumbing ----------

const TG = (token) => `https://api.telegram.org/bot${token}`;

async function tgSend(env, chatId, text, extra = {}) {
  const body = { chat_id: chatId, text, parse_mode: "HTML", disable_web_page_preview: true, ...extra };
  return fetch(`${TG(env[BOT_TOKEN])}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function tgAnswerCb(env, cbId, text) {
  return fetch(`${TG(env[BOT_TOKEN])}/answerCallbackQuery`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ callback_query_id: cbId, text }),
  });
}

async function tgEdit(env, chatId, msgId, text, extra = {}) {
  const body = { chat_id: chatId, message_id: msgId, text, parse_mode: "HTML", ...extra };
  return fetch(`${TG(env[BOT_TOKEN])}/editMessageText`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function tgAnswerInline(env, inlineQueryId, results) {
  return fetch(`${TG(env[BOT_TOKEN])}/answerInlineQuery`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      inline_query_id: inlineQueryId,
      results,
      cache_time: 30,
      is_personal: true,
    }),
  });
}

// ---------- Inline mode: live search as the user types ----------
// Triggered by Telegram itself once the user is in "@bot query" mode
// (see switch_inline_query_current_chat on the search button). Telegram
// shows these results in a small panel above the text field. The first
// TMDB result is the closest title match and is shown first; the rest are
// other titles matching the same letters, exactly like modern movie bots.
async function onInlineQuery(env, iq) {
  const query = (iq.query || "").trim();
  if (query.length < 2) {
    await tgAnswerInline(env, iq.id, []);
    return;
  }

  const r = await tmdb(env, "/search/multi", { query, include_adult: "false" });
  const raw = (r.ok ? (r.data.results || []) : []).filter((m) => m.media_type === "movie" || m.media_type === "tv");
  if (!raw.length) {
    await tgAnswerInline(env, iq.id, []);
    return;
  }

  // TMDB already ranks the best title match first; we just cap the list.
  const results = raw.slice(0, 20).map((m) => {
    const title = m.title || m.name;
    const yr = (m.release_date || m.first_air_date || "").slice(0, 4);
    const rating = m.vote_average ? ` ⭐${m.vote_average.toFixed(1)}` : "";
    const poster = m.poster_path ? `${POSTER_BASE}${m.poster_path}` : null;
    const icon = m.media_type === "tv" ? "📺" : "🎬";
    const caption = `${icon} <b>${escape(title)}</b> (${yr})${rating}`;
    const base = {
      id: `${m.media_type}:${m.id}`,
      title: `${title}${yr ? ` (${yr})` : ""}`,
      description: m.overview ? m.overview.slice(0, 100) : undefined,
      reply_markup: { inline_keyboard: [[{ text: "📋 جزئیات کامل", callback_data: `m:${m.media_type}:${m.id}` }]] },
    };
    if (poster) {
      return {
        type: "photo",
        photo_url: poster,
        thumbnail_url: poster,
        photo_width: 500,
        photo_height: 750,
        caption,
        parse_mode: "HTML",
        ...base,
      };
    }
    return {
      type: "article",
      input_message_content: { message_text: caption, parse_mode: "HTML" },
      ...base,
    };
  });

  await tgAnswerInline(env, iq.id, results);
}

const ENT = { [String.fromCharCode(38)]: String.fromCharCode(38,35,49,53,54,59),
                [String.fromCharCode(60)]: String.fromCharCode(38,108,116,59),
                [String.fromCharCode(62)]: String.fromCharCode(38,103,116,59),
                [String.fromCharCode(34)]: String.fromCharCode(38,113,117,111,116,59),
                [String.fromCharCode(39)]: String.fromCharCode(38,35,51,57,59) };
function escape(s = "") {
  return String(s).replace(/[&<>"']/g, (c) => ENT[c] || c);
}

// ---------- Cold start: Persian welcome + real colored menu (Mini App) ----------
//
// Telegram's Bot API has NO field for a button's background color — every
// inline_keyboard / reply_keyboard button always uses the client's own
// theme, full stop. The only way to get buttons that are actually green
// and actually blue is a Telegram Web App (Mini App): a normal webpage,
// styled with normal CSS, opened inside Telegram from a button. That's
// what /menu below serves. Tapping a button in it calls
// Telegram.WebApp.sendData(...), which arrives at the bot as a regular
// message with a `web_app_data` field — handled in handleUpdate().

function menuHomeButton(origin) {
  return { reply_markup: { inline_keyboard: [[
    { text: "📂  باز کردن منو", web_app: { url: `${origin}/menu` } },
  ]] } };
}

function menuHtml() {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover, user-scalable=no">
<title>دنیای فیلم</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0c10; --bg-elevated: #141820; --card: #1a1f2a; --card-hover: #222a38;
    --border: #2a3040; --text: #f0f0f5; --text-secondary: #8b8fa3;
    --accent: #e50914; --accent-hover: #f6121d; --gold: #d4a017; --gold-dim: #a08020;
    --radius: 12px; --radius-lg: 16px;
    --shadow: 0 4px 20px rgba(0,0,0,0.5); --shadow-lg: 0 8px 32px rgba(0,0,0,0.6);
    --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  }
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; margin: 0; padding: 0; }
  html, body { height: 100%; overflow: hidden; }
  body {
    font-family: 'Vazirmatn', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg); color: var(--text); display: flex; flex-direction: column;
  }
  .app-header {
    position: sticky; top: 0; z-index: 100;
    background: linear-gradient(180deg, var(--bg) 60%, transparent);
    padding: 16px 16px 8px; text-align: center; border-bottom: 1px solid var(--border);
  }
  .app-header h1 {
    font-size: 22px; font-weight: 900;
    background: linear-gradient(135deg, var(--accent), var(--gold));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
    letter-spacing: -0.5px;
  }
  .app-header .subtitle { font-size: 11px; color: var(--text-secondary); margin-top: 2px; font-weight: 500; }

  .scroll-area { flex: 1; overflow-y: auto; overflow-x: hidden; padding: 0 16px 100px; scroll-behavior: smooth; }
  .scroll-area::-webkit-scrollbar { width: 4px; }
  .scroll-area::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }

  .section { margin-bottom: 28px; }
  .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; padding: 0 4px; }
  .section-title { font-size: 15px; font-weight: 800; color: var(--text); display: flex; align-items: center; gap: 8px; }
  .section-title .icon { font-size: 18px; }
  .section-subtitle { font-size: 11px; color: var(--text-secondary); font-weight: 500; background: var(--card); padding: 4px 10px; border-radius: 20px; border: 1px solid var(--border); }
  .section-more { font-size: 12px; color: var(--accent); font-weight: 700; cursor: pointer; white-space: nowrap; margin-inline-start: 8px; }
  .section-more:active { opacity: 0.7; }
  .back-link { display: inline-block; font-size: 13px; color: var(--text-secondary); cursor: pointer; margin-bottom: 6px; }

  .poster-strip { display: flex; gap: 12px; overflow-x: auto; scroll-snap-type: x mandatory; padding: 4px 4px 16px; margin: 0 -4px; scrollbar-width: none; -ms-overflow-style: none; }
  .poster-strip::-webkit-scrollbar { display: none; }
  .poster-card { flex: 0 0 auto; width: 130px; scroll-snap-align: start; cursor: pointer; transition: var(--transition); }
  .poster-card:active { transform: scale(0.96); }
  .poster-card .thumb-wrap { position: relative; width: 100%; aspect-ratio: 2/3; border-radius: var(--radius); overflow: hidden; background: var(--card); border: 1px solid var(--border); box-shadow: var(--shadow); }
  .poster-card .thumb-wrap img { width: 100%; height: 100%; object-fit: cover; transition: transform 0.4s ease; }
  .poster-card:hover .thumb-wrap img { transform: scale(1.05); }
  .poster-card .rating-badge { position: absolute; top: 6px; right: 6px; background: rgba(0,0,0,0.75); backdrop-filter: blur(4px); color: var(--gold); font-size: 11px; font-weight: 700; padding: 3px 7px; border-radius: 8px; border: 1px solid rgba(212,160,23,0.3); }
  .poster-card .type-badge { position: absolute; top: 6px; left: 6px; background: rgba(229,9,20,0.85); color: #fff; font-size: 9px; font-weight: 700; padding: 2px 6px; border-radius: 6px; }
  .poster-card .poster-title { font-size: 12px; font-weight: 700; margin-top: 8px; line-height: 1.4; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text); }
  .poster-card .poster-meta { font-size: 11px; color: var(--text-secondary); margin-top: 2px; display: flex; align-items: center; gap: 6px; }

  .poster-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(104px, 1fr)); gap: 12px; }
  .poster-grid .poster-card { width: 100%; max-width: 150px; margin: 0 auto; }

  .playlist-toolbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; padding: 0 4px; min-height: 34px; gap: 10px; flex-wrap: wrap; }
  .playlist-sel-count { font-size: 12.5px; color: var(--text-secondary); font-weight: 600; }
  .playlist-toolbar-actions { display: flex; gap: 8px; }
  .btn-primary.sm, .btn-secondary.sm { flex: none; padding: 8px 14px; font-size: 12.5px; border-radius: 10px; }
  .btn-primary.sm:disabled { opacity: 0.45; cursor: not-allowed; }

  .poster-card.selectable { cursor: pointer; }
  .poster-card.selectable .thumb-wrap::after {
    content: ''; position: absolute; bottom: 6px; right: 6px; width: 22px; height: 22px;
    border-radius: 50%; border: 2px solid rgba(255,255,255,0.85); background: rgba(0,0,0,0.45);
    transition: var(--transition);
  }
  .poster-card.selectable.selected .thumb-wrap { box-shadow: 0 0 0 2px var(--accent); }
  .poster-card.selectable.selected .thumb-wrap::after {
    content: '✓'; background: var(--accent); border-color: var(--accent); color: #fff;
    display: flex; align-items: center; justify-content: center; font-size: 13px; font-weight: 900;
  }

  .sheet-overlay { position: fixed; inset: 0; z-index: 200; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); opacity: 0; pointer-events: none; transition: opacity 0.3s ease; }
  .sheet-overlay.active { opacity: 1; pointer-events: auto; }
  .bottom-sheet { position: fixed; left: 0; right: 0; bottom: 0; z-index: 201; background: linear-gradient(180deg, var(--bg-elevated), var(--bg)); border-radius: 24px 24px 0 0; border-top: 1px solid var(--border); box-shadow: 0 -8px 40px rgba(0,0,0,0.7); transform: translateY(100%); transition: transform 0.4s cubic-bezier(0.32, 0.72, 0, 1); max-height: 88vh; overflow-y: auto; padding-bottom: 80px; }
  .bottom-sheet.active { transform: translateY(0); }
  .bottom-sheet::-webkit-scrollbar { width: 4px; }
  .bottom-sheet::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
  .sheet-handle { width: 40px; height: 4px; background: var(--border); border-radius: 4px; margin: 12px auto 8px; }
  .sheet-content { padding: 0 20px 20px; }

  .detail-hero { position: relative; text-align: center; margin-bottom: 16px; }
  .detail-hero img { width: 160px; height: 240px; object-fit: cover; border-radius: var(--radius-lg); box-shadow: var(--shadow-lg); border: 2px solid var(--border); }
  .detail-hero .ph { width: 160px; height: 240px; border-radius: var(--radius-lg); background: var(--card); display: flex; align-items: center; justify-content: center; font-size: 48px; margin: 0 auto; border: 2px solid var(--border); }
  .detail-title { font-size: 20px; font-weight: 900; margin-top: 14px; color: var(--text); line-height: 1.3; }
  .detail-year { font-size: 13px; color: var(--text-secondary); margin-top: 4px; }
  .detail-stats { display: flex; gap: 8px; justify-content: center; flex-wrap: wrap; margin: 16px 0; }
  .stat-chip { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 8px 14px; font-size: 12px; text-align: center; min-width: 70px; }
  .stat-chip b { display: block; font-size: 14px; color: var(--gold); margin-bottom: 2px; }
  .detail-info { background: var(--card); border-radius: var(--radius-lg); padding: 16px; margin-bottom: 12px; border: 1px solid var(--border); }
  .detail-info .k { font-size: 11px; color: var(--gold-dim); margin-bottom: 4px; font-weight: 700; }
  .detail-info .v { font-size: 13.5px; line-height: 1.7; color: var(--text); }
  .link-list a { display: block; padding: 12px 14px; background: var(--card); border: 1px solid var(--border); border-radius: 10px; color: var(--accent); text-decoration: none; font-size: 12.5px; margin-bottom: 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; transition: var(--transition); }
  .link-list a:hover { border-color: var(--accent); background: var(--card-hover); }
  .sheet-actions { display: flex; gap: 10px; margin-top: 16px; }
  .btn-primary { flex: 1; padding: 14px; border-radius: 12px; border: none; background: linear-gradient(135deg, var(--accent), var(--accent-hover)); color: #fff; font-weight: 800; font-size: 14px; cursor: pointer; transition: var(--transition); }
  .btn-primary:active { transform: scale(0.97); opacity: 0.9; }
  .btn-secondary { flex: 1; padding: 14px; border-radius: 12px; border: 1px solid var(--border); background: var(--card); color: var(--text); font-weight: 700; font-size: 14px; cursor: pointer; transition: var(--transition); }
  .btn-secondary:active { background: var(--card-hover); }

  .bottom-nav-wrap { position: fixed; bottom: 16px; left: 16px; right: 16px; z-index: 150; display: flex; justify-content: center; }
  .bottom-nav { display: flex; align-items: center; gap: 2px; background: rgba(26, 31, 42, 0.92); backdrop-filter: blur(20px) saturate(1.2); border: 1px solid var(--border); border-radius: 50px; padding: 6px 8px; box-shadow: 0 8px 32px rgba(0,0,0,0.5); max-width: 100%; overflow-x: auto; scrollbar-width: none; -ms-overflow-style: none; }
  .bottom-nav::-webkit-scrollbar { display: none; }
  .nav-item { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 3px; padding: 8px 10px; min-width: 56px; border-radius: 40px; cursor: pointer; transition: var(--transition); border: none; background: transparent; color: var(--text-secondary); font-family: inherit; font-size: 10px; font-weight: 600; white-space: nowrap; }
  .nav-item .nav-icon { font-size: 20px; transition: transform 0.2s ease; }
  .nav-item:hover { color: var(--text); }
  .nav-item:hover .nav-icon { transform: translateY(-2px); }
  .nav-item.active { background: linear-gradient(135deg, var(--accent), #c10711); color: #fff; box-shadow: 0 4px 12px rgba(229,9,20,0.3); }
  .nav-item.active .nav-icon { transform: scale(1.1); }

  .random-stage { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 60vh; gap: 24px; }
  .slot-machine { display: flex; gap: 10px; perspective: 600px; }
  .slot-card { width: 90px; height: 135px; border-radius: 10px; background: var(--card); border: 2px solid var(--border); box-shadow: var(--shadow); overflow: hidden; position: relative; }
  .slot-reel { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; }
  .slot-reel span { flex: 0 0 135px; height: 135px; display: flex; align-items: center; justify-content: center; font-size: 32px; }
  .slot-card.spinning .slot-reel { animation: slotForward 0.5s linear infinite; }
  .slot-card:nth-child(1) .slot-reel { animation-duration: 0.45s; } .slot-card:nth-child(2) .slot-reel { animation-duration: 0.5s; }
  .slot-card:nth-child(3) .slot-reel { animation-duration: 0.4s; } .slot-card:nth-child(4) .slot-reel { animation-duration: 0.55s; }
  .slot-card:nth-child(5) .slot-reel { animation-duration: 0.48s; }
  @keyframes slotForward { 0% { transform: translateY(0); } 100% { transform: translateY(-135px); } }
  .slot-label { font-size: 16px; font-weight: 700; color: var(--text-secondary); animation: pulseText 1s infinite; }
  @keyframes pulseText { 0%, 100% { opacity: 0.5; } 50% { opacity: 1; } }
  .start-btn { padding: 16px 48px; border-radius: 50px; border: none; background: linear-gradient(135deg, var(--accent), var(--accent-hover)); color: #fff; font-size: 16px; font-weight: 800; cursor: pointer; box-shadow: 0 8px 24px rgba(229,9,20,0.35); transition: var(--transition); }
  .start-btn:active { transform: scale(0.95); }

  .loading-wrap { text-align: center; padding: 60px 20px; color: var(--text-secondary); }
  .spinner { width: 32px; height: 32px; border-radius: 50%; margin: 0 auto 14px; border: 3px solid var(--border); border-top-color: var(--accent); animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .empty-state { text-align: center; padding: 50px 20px; color: var(--text-secondary); font-size: 13px; }

  .search-wrap { position: sticky; top: 0; z-index: 90; background: linear-gradient(180deg, var(--bg) 70%, transparent); padding: 12px 16px 8px; margin-bottom: 8px; }
  .search-box { position: relative; width: 100%; }
  .search-box input { width: 100%; padding: 14px 46px 14px 16px; border-radius: 14px; border: 1px solid var(--border); background: var(--card); color: var(--text); font-size: 14.5px; outline: none; font-family: inherit; transition: var(--transition); }
  .search-box input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(229,9,20,0.15); }
  .search-box input::placeholder { color: var(--text-secondary); }
  .search-box .icon { position: absolute; right: 16px; top: 50%; transform: translateY(-50%); font-size: 16px; opacity: 0.6; pointer-events: none; }

  .genre-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }
  .genre-chip { padding: 16px; border-radius: var(--radius-lg); background: linear-gradient(135deg, var(--card), var(--card-hover)); border: 1px solid var(--border); text-align: center; font-size: 14px; font-weight: 700; cursor: pointer; color: var(--text); transition: var(--transition); display: flex; align-items: center; justify-content: center; gap: 8px; }
  .genre-chip:hover { border-color: var(--accent); transform: translateY(-2px); }
  .genre-chip:active { transform: scale(0.97); }

  .letter-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 8px; }
  .letter-btn { aspect-ratio: 1; border-radius: 10px; background: var(--card); border: 1px solid var(--border); display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 14px; cursor: pointer; color: var(--text); transition: var(--transition); }
  .letter-btn:hover { border-color: var(--accent); }
  .letter-btn:active { background: var(--accent); color: #fff; border-color: var(--accent); }

  .ai-chat { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 12px; }
  .ai-chat .msg { max-width: 85%; padding: 12px 16px; border-radius: 16px; font-size: 14px; line-height: 1.8; }
  .ai-chat .msg.user { align-self: flex-start; background: var(--card); border: 1px solid var(--border); color: var(--text); border-bottom-left-radius: 4px; }
  .ai-chat .msg.bot { align-self: flex-end; background: linear-gradient(135deg, #1a1520, #251a30); border: 1px solid #3a2a50; color: var(--text); border-bottom-right-radius: 4px; }
  .ai-input-wrap { padding: 12px 16px 20px; border-top: 1px solid var(--border); background: var(--bg); display: flex; gap: 10px; }
  .ai-input-wrap textarea { flex: 1; resize: none; background: var(--card); border: 1px solid var(--border); color: var(--text); border-radius: 14px; padding: 12px 14px; font-family: inherit; font-size: 14px; max-height: 100px; outline: none; }
  .ai-input-wrap textarea:focus { border-color: var(--accent); }
  .ai-input-wrap button { width: 44px; height: 44px; border-radius: 12px; border: none; background: var(--accent); color: #fff; font-size: 18px; cursor: pointer; }
  .ai-welcome { text-align: center; padding: 40px 20px; color: var(--text-secondary); }
  .ai-welcome .chips { display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; margin-top: 16px; }
  .ai-welcome .chip { border: 1px solid var(--border); color: var(--gold); background: transparent; padding: 8px 14px; border-radius: 20px; font-size: 12px; cursor: pointer; }

  .fade-in { animation: fadeIn 0.4s ease forwards; opacity: 0; }
  @keyframes fadeIn { to { opacity: 1; } }
  .slide-up { animation: slideUp 0.4s ease forwards; transform: translateY(20px); opacity: 0; }
  @keyframes slideUp { to { transform: translateY(0); opacity: 1; } }
  body.sheet-open .bottom-nav-wrap { transform: translateY(120px); transition: transform 0.3s ease; }
</style>
</head>
<body>

<div class="app-header" id="appHeader">
  <h1>🎬 دنیای فیلم</h1>
  <div class="subtitle">فیلم و سریال مورد نظرت رو پیدا کن</div>
</div>

<div class="scroll-area" id="scrollArea"></div>

<div class="sheet-overlay" id="sheetOverlay" onclick="closeSheet()"></div>
<div class="bottom-sheet" id="bottomSheet">
  <div class="sheet-handle"></div>
  <div class="sheet-content" id="sheetContent"></div>
</div>

<div class="bottom-nav-wrap" id="bottomNavWrap">
  <div class="bottom-nav">
    <button class="nav-item" data-nav="genres" onclick="navTo('genres')">
      <span class="nav-icon">🎭</span><span>ژانرها</span>
    </button>
    <button class="nav-item" data-nav="ai" onclick="navTo('ai')">
      <span class="nav-icon">🤖</span><span>هوش مصنوعی</span>
    </button>
    <button class="nav-item active" data-nav="home" onclick="navTo('home')">
      <span class="nav-icon">🏠</span><span>خانه</span>
    </button>
    <button class="nav-item" data-nav="search" onclick="navTo('search')">
      <span class="nav-icon">🔍</span><span>جستجو</span>
    </button>
    <button class="nav-item" data-nav="random" onclick="navTo('random')">
      <span class="nav-icon">🎲</span><span>تصادفی</span>
    </button>
    <button class="nav-item" data-nav="playlist" onclick="navTo('playlist')">
      <span class="nav-icon">📋</span><span>لیست پخش</span>
    </button>
  </div>
</div>

<script>
window.onerror = function(msg, src, line, col, err) {
  document.body.innerHTML = '<div style="direction:ltr;text-align:left;padding:20px;color:#fff;background:#111;font-family:monospace;font-size:12px;white-space:pre-wrap;line-height:1.6;">JS ERROR:\\n' + msg + '\\nline ' + line + ' col ' + col + '\\n' + (err && err.stack ? err.stack : '') + '</div>';
  return true;
};

var tg = (window.Telegram && window.Telegram.WebApp) || null;
if (tg) { tg.ready(); tg.expand(); }
function openExternal(url) {
  if (tg && tg.openLink) tg.openLink(url);
  else window.open(url, '_blank');
}

var API = '';
var currentView = 'home';
var navStack = [];
var lastSearchQ = '';

var scrollArea = document.getElementById('scrollArea');
var sheetOverlay = document.getElementById('sheetOverlay');
var bottomSheet = document.getElementById('bottomSheet');
var sheetContent = document.getElementById('sheetContent');
var appHeader = document.getElementById('appHeader');

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
function api(path) {
  return fetch(API + path).then(function(r) { return r.json(); });
}
function apiPost(path, body) {
  return fetch(API + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }).then(function(r) { return r.json(); });
}

function navTo(view, params) {
  if (view !== currentView) navStack.push({ view: currentView, params: {} });
  currentView = view;
  updateNavActive(view);
  render(view, params || {});
}
function updateNavActive(view) {
  document.querySelectorAll('.nav-item').forEach(function(el) {
    el.classList.toggle('active', el.dataset.nav === view);
  });
}

function openSheet(html) {
  sheetContent.innerHTML = html;
  document.body.classList.add('sheet-open');
  sheetOverlay.classList.add('active');
  bottomSheet.classList.add('active');
}
function closeSheet() {
  document.body.classList.remove('sheet-open');
  sheetOverlay.classList.remove('active');
  bottomSheet.classList.remove('active');
  setTimeout(function() { sheetContent.innerHTML = ''; }, 300);
}

function posterCard(m, size) {
  var isTv = m.type === 'tv';
  var thumb = m.poster
    ? '<div class="thumb-wrap"><img loading="lazy" src="' + m.poster + '" alt=""><span class="rating-badge">⭐ ' + m.rating + '</span><span class="type-badge">' + (isTv ? 'سریال' : 'فیلم') + '</span></div>'
    : '<div class="thumb-wrap" style="display:flex;align-items:center;justify-content:center;font-size:36px;">' + (isTv ? '📺' : '🎬') + '</div>';
  return (
    '<div class="poster-card ' + (size || '') + '" data-id="' + m.id + '" data-type="' + (m.type || 'movie') + '" onclick="openDetail(' + m.id + ', \\'' + (m.type || 'movie') + '\\')">' +
      thumb +
      '<div class="poster-title">' + (isTv ? '📺 ' : '') + esc(m.title) + '</div>' +
      '<div class="poster-meta"><span>' + esc(m.year || '') + '</span><span>⭐ ' + (m.rating || '—') + '</span></div>' +
    '</div>'
  );
}

function posterStrip(items) {
  if (!items || !items.length) return '<div class="empty-state">موردی پیدا نشد</div>';
  return '<div class="poster-strip">' + items.map(function(m) { return posterCard(m); }).join('') + '</div>';
}

function posterGrid(items) {
  if (!items || !items.length) return '<div class="empty-state">موردی پیدا نشد</div>';
  return '<div class="poster-grid">' + items.map(function(m) { return posterCard(m); }).join('') + '</div>';
}

function openDetail(id, type) {
  openSheet('<div class="loading-wrap"><div class="spinner"></div>در حال بارگذاری...</div>');
  api('/api/movie?id=' + encodeURIComponent(id) + '&type=' + encodeURIComponent(type)).then(function(res) {
    if (!res.ok) { sheetContent.innerHTML = '<div class="empty-state">خطا: ' + esc(res.error) + '</div>'; return; }
    renderDetailSheet(res);
  }).catch(function(e) {
    sheetContent.innerHTML = '<div class="empty-state">خطا در بارگذاری</div>';
  });
}

function renderDetailSheet(res) {
  var d = res.detail;
  var isTv = d.type === 'tv';
  var subs = res.subtitles || { filmo: [], subtitlecat: [] };
  var html = [];

  html.push('<div class="detail-hero">');
  if (d.poster) html.push('<img src="' + d.poster + '" alt="">');
  else html.push('<div class="ph">' + (isTv ? '📺' : '🎬') + '</div>');
  html.push('<div class="detail-title">' + (isTv ? '📺 ' : '') + esc(d.title) + '</div>');
  html.push('<div class="detail-year">' + esc(d.year || '') + '</div>');
  html.push('</div>');

  html.push('<div class="detail-stats">');
  html.push('<div class="stat-chip"><b>⭐ ' + esc(d.rating || '—') + '</b>امتیاز</div>');
  if (isTv) {
    html.push('<div class="stat-chip"><b>' + esc(d.seasons || '?') + '</b>فصل</div>');
    html.push('<div class="stat-chip"><b>' + esc(d.episodes || '?') + '</b>قسمت</div>');
  } else {
    html.push('<div class="stat-chip"><b>' + esc(d.runtime || '?') + '</b>دقیقه</div>');
  }
  html.push('<div class="stat-chip"><b>' + esc(d.votes || 0) + '</b>رای</div>');
  html.push('</div>');

  if (d.genres) html.push('<div class="detail-info"><div class="k">ژانر</div><div class="v">' + esc(d.genres) + '</div></div>');
  if (d.directors) html.push('<div class="detail-info"><div class="k">' + (isTv ? 'سازنده' : 'کارگردان') + '</div><div class="v">' + esc(d.directors) + '</div></div>');
  if (d.cast) html.push('<div class="detail-info"><div class="k">بازیگران</div><div class="v">' + esc(d.cast) + '</div></div>');
  if (d.overview) html.push('<div class="detail-info"><div class="k">خلاصه داستان</div><div class="v">' + esc(d.overview) + '</div></div>');

  var links = [];
  (subs.filmo || []).forEach(function(u) { links.push('<a href="' + esc(u) + '" target="_blank" onclick="event.stopPropagation();openExternal(this.href)">🇮🇷 ' + esc(u) + '</a>'); });
  (subs.subtitlecat || []).forEach(function(u) { links.push('<a href="' + esc(u) + '" target="_blank" onclick="event.stopPropagation();openExternal(this.href)">🔤 ' + esc(u) + '</a>'); });
  if (links.length) {
    html.push('<div class="detail-info"><div class="k">📥 لینک‌های زیرنویس فارسی</div><div class="link-list">' + links.join('') + '</div></div>');
  }

  html.push('<div class="detail-info"><div class="k">دانلود فیلم/سریال</div><div class="link-list"><a href="https://filmo.ir" target="_blank" onclick="event.stopPropagation();openExternal(this.href)">📦 filmo.ir</a><a href="https://subf2m.co" target="_blank" onclick="event.stopPropagation();openExternal(this.href)">📦 subf2m.co</a></div></div>');
  html.push('<div style="text-align:center;color:var(--text-secondary);font-size:11px;margin:-8px 0 12px;">برای دانلود این فیلم/سریال می‌توانید از طریق این دو سایت اقدام کنید</div>');

  if (d.imdb) html.push('<a href="https://www.imdb.com/title/' + d.imdb + '" target="_blank" onclick="event.stopPropagation();openExternal(this.href)" style="display:block;text-align:center;color:var(--text-secondary);font-size:12px;margin:8px 0 14px;">مشاهده در IMDB</a>');

  html.push('<div class="sheet-actions">');
  html.push('<button class="btn-secondary" onclick="closeSheet()">بستن</button>');
  html.push('<button class="btn-primary" id="saveBtn" onclick="saveToPlaylist(this)">📋 ذخیره در لیست پخش</button>');
  html.push('</div>');

  sheetContent.innerHTML = html.join('');
  window._currentDetail = d;
}

function saveToPlaylist(btn) {
  var d = window._currentDetail;
  if (!d) return;
  if (!tg || !tg.initData) { btn.textContent = '⚠️ برای ذخیره، منو را از داخل تلگرام باز کنید'; return; }
  btn.disabled = true;
  btn.textContent = 'در حال ذخیره...';
  apiPost('/api/playlist', {
    initData: tg.initData,
    item: { id: d.id, type: d.type, title: d.title, year: d.year, poster: d.poster, rating: d.rating }
  }).then(function(res) {
    if (res.ok) { btn.textContent = '✅ ذخیره شد'; }
    else { btn.textContent = '❌ ' + (res.error || 'خطا'); btn.disabled = false; }
  }).catch(function() {
    btn.textContent = '❌ خطا در اتصال'; btn.disabled = false;
  });
}

function render(view, params) {
  scrollArea.innerHTML = '';
  appHeader.style.display = 'flex';

  if (view === 'home') renderHome();
  else if (view === 'search') renderSearch();
  else if (view === 'genres') renderGenres();
  else if (view === 'letters') renderLetters(params);
  else if (view === 'genreResults') renderGenreResults(params);
  else if (view === 'popular') renderSimpleList('/api/popular', '🔥 پرطرفدارترین‌ها', 'فیلم و سریال‌های پرطرفدار این لحظه');
  else if (view === 'now_playing') renderSimpleList('/api/now_playing', '🎞 در حال اکران', 'فیلم و سریال‌های در حال پخش');
  else if (view === 'upcoming') renderSimpleList('/api/upcoming', '📅 به‌زودی', 'فیلم و سریال‌های آینده');
  else if (view === 'playlist') renderPlaylist();
  else if (view === 'suggestions') renderSuggestionsView();
  else if (view === 'random') renderRandom();
  else if (view === 'ai') renderAI();
  else if (view === 'fullList') renderFullList(params);
}

function renderHome() {
  appHeader.innerHTML = '<h1>🎬 دنیای فیلم</h1><div class="subtitle">فیلم و سریال مورد نظرت رو پیدا کن</div>';

  var html = [];
  html.push('<div class="section slide-up" style="animation-delay:0.05s">');
  html.push('<div class="section-header"><div class="section-title"><span class="icon">🏆</span>پیشنهاد امروز</div><span class="section-subtitle">۵۰ فیلم و سریال برتر</span><span class="section-more" onclick="navTo(\\'fullList\\', {kind:\\'top\\', icon:\\'🏆\\', title:\\'پیشنهاد امروز\\', subtitle:\\'۵۰ فیلم و سریال برتر\\'})">مشاهده همه ›</span></div>');
  html.push('<div id="sec-suggest">' + loadingHtml() + '</div>');
  html.push('</div>');

  html.push('<div class="section slide-up" style="animation-delay:0.15s">');
  html.push('<div class="section-header"><div class="section-title"><span class="icon">🔥</span>پرطرفدارها</div><span class="section-subtitle">۵۰ فیلم و سریال محبوب</span><span class="section-more" onclick="navTo(\\'fullList\\', {kind:\\'popular\\', icon:\\'🔥\\', title:\\'پرطرفدارها\\', subtitle:\\'۵۰ فیلم و سریال محبوب\\'})">مشاهده همه ›</span></div>');
  html.push('<div id="sec-popular">' + loadingHtml() + '</div>');
  html.push('</div>');

  html.push('<div class="section slide-up" style="animation-delay:0.25s">');
  html.push('<div class="section-header"><div class="section-title"><span class="icon">🎞</span>در حال اکران</div><span class="section-more" onclick="navTo(\\'fullList\\', {kind:\\'now_playing\\', icon:\\'🎞\\', title:\\'در حال اکران\\', subtitle:\\'فیلم و سریال‌های در حال پخش\\'})">مشاهده همه ›</span></div>');
  html.push('<div id="sec-now">' + loadingHtml() + '</div>');
  html.push('</div>');

  html.push('<div class="section slide-up" style="animation-delay:0.35s">');
  html.push('<div class="section-header"><div class="section-title"><span class="icon">📅</span>به‌زودی</div><span class="section-more" onclick="navTo(\\'fullList\\', {kind:\\'upcoming\\', icon:\\'📅\\', title:\\'به‌زودی\\', subtitle:\\'فیلم و سریال‌های آینده\\'})">مشاهده همه ›</span></div>');
  html.push('<div id="sec-upcoming">' + loadingHtml() + '</div>');
  html.push('</div>');

  scrollArea.innerHTML = html.join('');

  loadHomeSection('sec-suggest', '/api/suggestions', function(res) {
    var all = (res.top || []).concat(res.popular || []);
    return posterStrip(all.slice(0, 50));
  });
  loadHomeSection('sec-popular', '/api/popular', function(res) {
    return posterStrip((res.results || []).slice(0, 50));
  });
  loadHomeSection('sec-now', '/api/now_playing', function(res) {
    return posterGrid(res.results || []);
  });
  loadHomeSection('sec-upcoming', '/api/upcoming', function(res) {
    return posterGrid(res.results || []);
  });
}

function loadHomeSection(id, path, renderer) {
  api(path).then(function(res) {
    var el = document.getElementById(id);
    if (el) el.innerHTML = res.ok ? renderer(res) : '<div class="empty-state">خطا در بارگذاری</div>';
  }).catch(function() {
    var el = document.getElementById(id);
    if (el) el.innerHTML = '<div class="empty-state">خطا در اتصال</div>';
  });
}

function loadingHtml() {
  return '<div class="loading-wrap"><div class="spinner"></div>در حال بارگذاری...</div>';
}

function renderSearch() {
  appHeader.innerHTML = '<div class="search-wrap"><div class="search-box"><span class="icon">🔍</span><input type="text" id="searchInput" placeholder="اسم فیلم یا سریال..." inputmode="search" enterkeyhint="search"></div></div>';
  scrollArea.innerHTML = '<div id="searchResults"></div>';

  var input = document.getElementById('searchInput');
  input.focus();
  input.addEventListener('keydown', function(e) {
    if (e.key !== 'Enter') return;
    var q = input.value.trim();
    if (q.length < 2) return;
    lastSearchQ = q;
    doSearch(q);
  });
}

function doSearch(q) {
  var container = document.getElementById('searchResults');
  container.innerHTML = loadingHtml();
  api('/api/search?q=' + encodeURIComponent(q)).then(function(res) {
    if (!res.ok) { container.innerHTML = '<div class="empty-state">خطا: ' + esc(res.error) + '</div>'; return; }
    if (!res.top) { container.innerHTML = '<div class="empty-state">نتیجه‌ای پیدا نشد</div>'; return; }

    var html = [];
    html.push('<div class="section">');
    html.push('<div class="section-header"><div class="section-title"><span class="icon">🎯</span>بهترین تطابق</div></div>');
    html.push('<div style="display:flex;justify-content:center;">' + posterCard(res.top, 'fade-in') + '</div>');
    html.push('</div>');

    if (res.others && res.others.length) {
      html.push('<div class="section">');
      html.push('<div class="section-header"><div class="section-title"><span class="icon">🔎</span>نتایج مشابه</div><span class="section-subtitle">' + res.others.length + ' مورد</span></div>');
      html.push(posterGrid(res.others));
      html.push('</div>');
    }
    container.innerHTML = html.join('');
  }).catch(function() {
    container.innerHTML = '<div class="empty-state">خطا در جستجو</div>';
  });
}

function renderGenres() {
  appHeader.innerHTML = '<h1>🎭 ژانرها</h1><div class="subtitle">یک ژانر انتخاب کنید</div>';
  scrollArea.innerHTML = loadingHtml();
  api('/api/genres').then(function(res) {
    if (!res.ok || !res.genres.length) { scrollArea.innerHTML = '<div class="empty-state">خطا در دریافت ژانرها</div>'; return; }
    var html = '<div class="genre-grid">' + res.genres.map(function(g) {
      return '<div class="genre-chip" data-gid="' + g.id + '" data-gname="' + esc(g.name) + '">🎬 ' + esc(g.name) + '</div>';
    }).join('') + '</div>';
    scrollArea.innerHTML = html;
    scrollArea.querySelectorAll('.genre-chip').forEach(function(el) {
      el.addEventListener('click', function() {
        navTo('letters', { gid: this.dataset.gid, gname: this.dataset.gname });
      });
    });
  }).catch(function() {
    scrollArea.innerHTML = '<div class="empty-state">خطا در اتصال</div>';
  });
}

function renderLetters(params) {
  appHeader.innerHTML = '<h1>🎭 ' + esc(params.gname) + '</h1><div class="subtitle">حرف اول اسم فیلم را انتخاب کنید</div>';
  var letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
  var html = '<div class="letter-grid">' + letters.map(function(l) {
    return '<div class="letter-btn" data-letter="' + l + '">' + l + '</div>';
  }).join('') + '</div>';
  scrollArea.innerHTML = html;
  scrollArea.querySelectorAll('.letter-btn').forEach(function(el) {
    el.addEventListener('click', function() {
      navTo('genreResults', { gid: params.gid, gname: params.gname, letter: this.dataset.letter });
    });
  });
}

function renderGenreResults(params) {
  appHeader.innerHTML = '<h1>🎭 ' + esc(params.gname) + ' · ' + params.letter + '</h1>';
  scrollArea.innerHTML = loadingHtml();
  api('/api/genre-letter?gid=' + encodeURIComponent(params.gid) + '&letter=' + encodeURIComponent(params.letter)).then(function(res) {
    if (!res.ok || !res.results.length) {
      scrollArea.innerHTML = '<div class="empty-state">فیلمی با حرف ' + params.letter + ' در این ژانر پیدا نشد.</div>';
      return;
    }
    scrollArea.innerHTML = posterGrid(res.results);
  }).catch(function() {
    scrollArea.innerHTML = '<div class="empty-state">خطا در اتصال</div>';
  });
}

function renderSimpleList(apiPath, title, subtitle) {
  appHeader.innerHTML = '<h1>' + esc(title) + '</h1><div class="subtitle">' + esc(subtitle) + '</div>';
  scrollArea.innerHTML = loadingHtml();
  api(apiPath).then(function(res) {
    if (!res.ok || !res.results.length) { scrollArea.innerHTML = '<div class="empty-state">موردی پیدا نشد</div>'; return; }
    scrollArea.innerHTML = posterGrid(res.results);
  }).catch(function() {
    scrollArea.innerHTML = '<div class="empty-state">خطا در اتصال</div>';
  });
}

function renderFullList(params) {
  params = params || {};
  appHeader.innerHTML =
    '<h1>' + esc(params.icon || '') + ' ' + esc(params.title || '') + '</h1>' +
    '<div class="subtitle">' + esc(params.subtitle || '') + '</div>';
  scrollArea.innerHTML =
    '<span class="back-link" onclick="navTo(\\'home\\')">‹ بازگشت به خانه</span>' + loadingHtml();
  api('/api/full-list?kind=' + encodeURIComponent(params.kind || '')).then(function(res) {
    var back = '<span class="back-link" onclick="navTo(\\'home\\')">‹ بازگشت به خانه</span>';
    if (!res.ok || !res.results.length) { scrollArea.innerHTML = back + '<div class="empty-state">موردی پیدا نشد</div>'; return; }
    scrollArea.innerHTML = back + posterGrid(res.results);
  }).catch(function() {
    scrollArea.innerHTML = '<span class="back-link" onclick="navTo(\\'home\\')">‹ بازگشت به خانه</span><div class="empty-state">خطا در اتصال</div>';
  });
}

var playlistSelectMode = false;
var playlistSelectedKeys = {};
var playlistItemsCache = [];

function notify(msg) {
  if (tg && tg.showAlert) tg.showAlert(msg);
  else alert(msg);
}

function playlistKey(m) { return (m.type || 'movie') + ':' + m.id; }

function renderPlaylist() {
  appHeader.innerHTML = '<h1>📋 لیست پخش من</h1><div class="subtitle">فیلم‌ها و سریال‌های ذخیره‌شده</div>';
  scrollArea.innerHTML = loadingHtml();
  playlistSelectMode = false;
  playlistSelectedKeys = {};
  if (!tg || !tg.initData) {
    scrollArea.innerHTML = '<div class="empty-state">برای دیدن لیست پخش، این صفحه را از داخل ربات تلگرام (نه مرورگر) باز کنید.</div>';
    return;
  }
  api('/api/playlist?initData=' + encodeURIComponent(tg.initData)).then(function(res) {
    if (!res.ok) { scrollArea.innerHTML = '<div class="empty-state">' + esc(res.error || 'خطا در اتصال') + '</div>'; return; }
    playlistItemsCache = res.results || [];
    if (!playlistItemsCache.length) { scrollArea.innerHTML = '<div class="empty-state">لیست پخش خالی است. از صفحه جزئیات فیلم‌ها می‌توانید اضافه کنید.</div>'; return; }
    renderPlaylistGrid();
  }).catch(function() {
    scrollArea.innerHTML = '<div class="empty-state">خطا در اتصال</div>';
  });
}

function renderPlaylistGrid() {
  var selCount = Object.keys(playlistSelectedKeys).length;
  var toolbar = playlistSelectMode
    ? (
        '<div class="playlist-toolbar">' +
          '<span class="playlist-sel-count">' + selCount + ' مورد انتخاب شد</span>' +
          '<div class="playlist-toolbar-actions">' +
            '<button class="btn-secondary sm" onclick="togglePlaylistSelectMode()">انصراف</button>' +
            '<button class="btn-primary sm" id="playlistDeleteBtn" ' + (selCount ? '' : 'disabled') + ' onclick="deleteSelectedFromPlaylist()">🗑 حذف (' + selCount + ')</button>' +
          '</div>' +
        '</div>'
      )
    : (
        '<div class="playlist-toolbar">' +
          '<span></span>' +
          '<span class="section-more" onclick="togglePlaylistSelectMode()">✓ انتخاب و حذف</span>' +
        '</div>'
      );

  scrollArea.innerHTML = toolbar + posterGrid(playlistItemsCache);

  if (playlistSelectMode) {
    scrollArea.querySelectorAll('.poster-card').forEach(function(el) {
      var key = el.dataset.type + ':' + el.dataset.id;
      el.classList.add('selectable');
      if (playlistSelectedKeys[key]) el.classList.add('selected');
      el.onclick = function(e) { e.preventDefault(); e.stopPropagation(); togglePlaylistCard(key, el); };
    });
  }
}

function togglePlaylistSelectMode() {
  playlistSelectMode = !playlistSelectMode;
  playlistSelectedKeys = {};
  renderPlaylistGrid();
}

function togglePlaylistCard(key, el) {
  if (playlistSelectedKeys[key]) { delete playlistSelectedKeys[key]; el.classList.remove('selected'); }
  else { playlistSelectedKeys[key] = true; el.classList.add('selected'); }
  var count = Object.keys(playlistSelectedKeys).length;
  var countEl = document.querySelector('.playlist-sel-count');
  if (countEl) countEl.textContent = count + ' مورد انتخاب شد';
  var delBtn = document.getElementById('playlistDeleteBtn');
  if (delBtn) { delBtn.textContent = '🗑 حذف (' + count + ')'; delBtn.disabled = !count; }
}

function deleteSelectedFromPlaylist() {
  var keys = Object.keys(playlistSelectedKeys);
  if (!keys.length || !tg || !tg.initData) return;
  var items = keys.map(function(k) {
    var idx = k.indexOf(':');
    return { type: k.slice(0, idx), id: Number(k.slice(idx + 1)) };
  });
  var delBtn = document.getElementById('playlistDeleteBtn');
  if (delBtn) { delBtn.disabled = true; delBtn.textContent = 'در حال حذف...'; }
  apiPost('/api/playlist-remove', { initData: tg.initData, items: items }).then(function(res) {
    if (!res.ok) { notify(res.error || 'حذف انجام نشد'); if (delBtn) { delBtn.disabled = false; } return; }
    playlistItemsCache = playlistItemsCache.filter(function(m) { return !playlistSelectedKeys[playlistKey(m)]; });
    playlistSelectMode = false;
    playlistSelectedKeys = {};
    if (!playlistItemsCache.length) {
      scrollArea.innerHTML = '<div class="empty-state">لیست پخش خالی است. از صفحه جزئیات فیلم‌ها می‌توانید اضافه کنید.</div>';
      return;
    }
    renderPlaylistGrid();
  }).catch(function() {
    notify('خطا در اتصال');
    if (delBtn) delBtn.disabled = false;
  });
}

function renderSuggestionsView() {
  appHeader.innerHTML = '<h1>🏆 پیشنهاد امروز</h1><div class="subtitle">برترین‌ها + محبوب‌ترین‌های روز</div>';
  scrollArea.innerHTML = loadingHtml();
  api('/api/suggestions').then(function(res) {
    if (!res.ok) { scrollArea.innerHTML = '<div class="empty-state">خطا</div>'; return; }
    var html = [];
    html.push('<div class="section"><div class="section-header"><div class="section-title"><span class="icon">🏆</span>برترین‌های TMDB</div></div>');
    html.push(posterStrip(res.top || []));
    html.push('</div>');
    html.push('<div class="section"><div class="section-header"><div class="section-title"><span class="icon">🔥</span>محبوب‌ترین روز</div></div>');
    html.push(posterStrip(res.popular || []));
    html.push('</div>');
    scrollArea.innerHTML = html.join('');
  }).catch(function() {
    scrollArea.innerHTML = '<div class="empty-state">خطا در اتصال</div>';
  });
}

function renderRandom() {
  appHeader.innerHTML = '<h1>🎲 پیشنهاد تصادفی</h1><div class="subtitle">یک فیلم یا سریال تصادفی برای شما</div>';
  scrollArea.innerHTML =
    '<div class="random-stage">' +
      '<div class="slot-machine">' +
        '<div class="slot-card"><div class="slot-reel"><span>🎬</span></div></div>' +
        '<div class="slot-card"><div class="slot-reel"><span>📺</span></div></div>' +
        '<div class="slot-card"><div class="slot-reel"><span>🎭</span></div></div>' +
        '<div class="slot-card"><div class="slot-reel"><span>⭐</span></div></div>' +
        '<div class="slot-card"><div class="slot-reel"><span>🍿</span></div></div>' +
      '</div>' +
      '<div class="slot-label">برای شروع دکمه زیر را بزنید</div>' +
      '<button class="start-btn" onclick="startRandom()">🎲 شروع</button>' +
    '</div>';
}

function startRandom() {
  var stage = document.querySelector('.random-stage');
  stage.innerHTML =
    '<div class="random-stage">' +
      '<div class="slot-machine">' +
        '<div class="slot-card spinning"><div class="slot-reel"><span>🎬</span><span>🎬</span></div></div>' +
        '<div class="slot-card spinning"><div class="slot-reel"><span>📺</span><span>📺</span></div></div>' +
        '<div class="slot-card spinning"><div class="slot-reel"><span>🎭</span><span>🎭</span></div></div>' +
        '<div class="slot-card spinning"><div class="slot-reel"><span>⭐</span><span>⭐</span></div></div>' +
        '<div class="slot-card spinning"><div class="slot-reel"><span>🍿</span><span>🍿</span></div></div>' +
      '</div>' +
      '<div class="slot-label">در حال انتخاب...</div>' +
    '</div>';

  api('/api/random').then(function(res) {
    if (!res.ok) { stage.innerHTML = '<div class="empty-state">خطا: ' + esc(res.error) + '</div>'; return; }
    setTimeout(function() {
      openDetail(res.detail.id, res.detail.type);
      setTimeout(function() { renderRandom(); }, 500);
    }, 1500);
  }).catch(function() {
    stage.innerHTML = '<div class="empty-state">خطا در اتصال</div>';
  });
}

function renderAI() {
  appHeader.innerHTML = '<h1>🤖 دستیار هوش مصنوعی</h1><div class="subtitle">گفتگوی آزاد درباره فیلم و سریال</div>';
  scrollArea.innerHTML =
    '<div class="ai-chat" id="aiChat">' +
      '<div class="ai-welcome">' +
        'هر سوالی درباره فیلم، سریال، کارگردان یا بازیگر داری بپرس.' +
        '<div class="chips">' +
          '<button class="chip" onclick="sendAiMsg(\\'بهترین سریال‌های جنایی-روانشناختی ده سال اخیر رو معرفی کن\\')">سریال جنایی خوب</button>' +
          '<button class="chip" onclick="sendAiMsg(\\'فیلم‌های کریستوفر نولان رو رتبه‌بندی کن\\')">فیلم‌های نولان</button>' +
          '<button class="chip" onclick="sendAiMsg(\\'یک فیلم مشابه Inception پیشنهاد بده\\')">مشابه Inception</button>' +
        '</div>' +
      '</div>' +
    '</div>' +
    '<div class="ai-input-wrap">' +
      '<textarea id="aiInput" rows="1" placeholder="مثلا: بهترین فیلم‌های کیارستمی کدوماند؟"></textarea>' +
      '<button onclick="submitAi()">↑</button>' +
    '</div>';

  var input = document.getElementById('aiInput');
  input.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submitAi(); }
  });
  input.addEventListener('input', function() {
    input.style.height = 'auto'; input.style.height = Math.min(input.scrollHeight, 100) + 'px';
  });
}

var aiHistory = [];
function sendAiMsg(text) {
  var chat = document.getElementById('aiChat');
  var welcome = chat.querySelector('.ai-welcome');
  if (welcome) welcome.remove();

  var userDiv = document.createElement('div');
  userDiv.className = 'msg user'; userDiv.textContent = text;
  chat.appendChild(userDiv); chat.scrollTop = chat.scrollHeight;

  aiHistory.push({ role: 'user', content: text });

  var typingDiv = document.createElement('div');
  typingDiv.className = 'msg bot'; typingDiv.innerHTML = '<div class="spinner" style="width:18px;height:18px;border-width:2px;margin:0;"></div>';
  chat.appendChild(typingDiv); chat.scrollTop = chat.scrollHeight;

  apiPost('/api/ai', { messages: aiHistory }).then(function(res) {
    typingDiv.remove();
    if (res.ok) {
      var botDiv = document.createElement('div');
      botDiv.className = 'msg bot'; botDiv.textContent = res.reply;
      chat.appendChild(botDiv); chat.scrollTop = chat.scrollHeight;
      aiHistory.push({ role: 'assistant', content: res.reply });
    } else {
      var errDiv = document.createElement('div');
      errDiv.className = 'msg bot'; errDiv.textContent = 'خطا: ' + (res.error || 'پاسخی دریافت نشد');
      chat.appendChild(errDiv); chat.scrollTop = chat.scrollHeight;
    }
  }).catch(function() {
    typingDiv.remove();
    var errDiv = document.createElement('div');
    errDiv.className = 'msg bot'; errDiv.textContent = 'ارتباط با سرور برقرار نشد.';
    chat.appendChild(errDiv); chat.scrollTop = chat.scrollHeight;
  });
}
function submitAi() {
  var input = document.getElementById('aiInput');
  var text = input.value.trim();
  if (!text) return;
  input.value = ''; input.style.height = 'auto';
  sendAiMsg(text);
}

render('home');
</script>
</body>
</html>`;
}



async function sendMenu(env, chatId, user, origin) {
  // BUG FIX: this message used to tell the user to tap the ☰ menu button,
  // but (a) no reply_markup/button was ever attached to this message, and
  // (b) the bot never called Telegram's setChatMenuButton API to make that
  // ☰ icon open the Mini App in the first place. Net result: after /start
  // the user had literally no working button anywhere. Fix: attach a real
  // inline "باز کردن منو" button (menuHomeButton) so there's always a
  // guaranteed way to open the Mini App.
  const greeting =
    `╔══════════════════════════╗\n` +
    `║ 🄼 🄾 🆅 🅸 🄴   🅱 🄾 🆃 ║\n` +
    `╚══════════════════════════╝\n\n` +
    `سلام ${user?.first_name ? escape(user.first_name) : ""} 👋\n\n` +
    `برای استفاده از ربات، روی دکمه‌ی زیر بزن، یا از منوی 📎 کنار جعبه پیام استفاده کن.`;
  await tgSend(env, chatId, greeting, menuHomeButton(origin));
}

// Configures Telegram's own persistent ☰ chat-menu button (next to the
// message box) to open the Mini App directly. Without this call the ☰
// button either doesn't exist or does nothing bot-related — it is NOT
// automatically wired up just because /menu exists as a route. Calling
// this with no chat_id sets the default for every user of the bot; call
// it once (e.g. via /setup-webhook) after each deploy.
async function tgSetMenuButton(env, origin) {
  return fetch(`${TG(env[BOT_TOKEN])}/setChatMenuButton`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      menu_button: { type: "web_app", text: "منو", web_app: { url: `${origin}/menu` } },
    }),
  });
}

// ---------- Search flow ----------

async function enterSearchMode(env, chatId, msgId) {
  const text = "🔍 <b>جستجوی فیلم / سریال</b>\n\nاسم فیلم یا سریال رو بنویس:";
  const kb = { reply_markup: { inline_keyboard: [[{ text: "🔙 بازگشت", callback_data: "menu:home" }]] } };
  if (msgId) await tgEdit(env, chatId, msgId, text, kb);
  else await tgSend(env, chatId, text, kb);
}

// Per-chat state: which mode they're in
async function getState(env, chatId) {
  const kv = env.STATE_KV;
  if (!kv) return null;
  const v = await kv.get(`s:${chatId}`);
  return v ? JSON.parse(v) : null;
}
async function setState(env, chatId, state) {
  const kv = env.STATE_KV;
  if (!kv) return;
  await kv.put(`s:${chatId}`, JSON.stringify(state), { expirationTtl: 1800 });
}

// Per-user playlist ("watch list"). Keyed by the Telegram user id (same
// value as chatId in a private chat), so every user's list is fully
// separate from everyone else's. No TTL — this is meant to persist.
async function getPlaylist(env, uid) {
  const kv = env.STATE_KV;
  if (!kv || !uid) return [];
  const v = await kv.get(`pl:${uid}`);
  return v ? JSON.parse(v) : [];
}
async function addToPlaylist(env, uid, item) {
  const kv = env.STATE_KV;
  if (!kv || !uid || !item?.id) return false;
  const list = await getPlaylist(env, uid);
  if (!list.some((x) => x.id === item.id && x.type === item.type)) {
    list.unshift({ id: item.id, type: item.type || "movie", title: item.title || "", year: item.year || "", poster: item.poster || null, rating: item.rating ?? null });
  }
  await kv.put(`pl:${uid}`, JSON.stringify(list.slice(0, 200)));
  return true;
}
async function removeFromPlaylist(env, uid, items) {
  const kv = env.STATE_KV;
  if (!kv || !uid || !Array.isArray(items) || !items.length) return false;
  const list = await getPlaylist(env, uid);
  const removeSet = new Set(items.map((x) => `${x.type || "movie"}:${x.id}`));
  const filtered = list.filter((x) => !removeSet.has(`${x.type || "movie"}:${x.id}`));
  await kv.put(`pl:${uid}`, JSON.stringify(filtered));
  return true;
}

async function apiPlaylist(request, env, url) {
  const initData = url.searchParams.get("initData") || "";
  const user = await verifyTelegramInitData(initData, env[BOT_TOKEN]);
  if (!user) return { ok: false, error: "احراز هویت نامعتبر است. لطفاً Mini App را از تلگرام دوباره باز کنید." };
  return { ok: true, results: await getPlaylist(env, user.id) };
}
async function apiPlaylistAdd(request, env) {
  let body;
  try { body = await request.json(); } catch { return { ok: false, error: "بدنه درخواست نامعتبر است" }; }
  const user = await verifyTelegramInitData(body?.initData, env[BOT_TOKEN]);
  if (!user) return { ok: false, error: "احراز هویت نامعتبر است. لطفاً Mini App را از تلگرام دوباره باز کنید." };
  if (!body?.item) return { ok: false, error: "اطلاعات ناقص است" };
  const saved = await addToPlaylist(env, user.id, body.item);
  return saved ? { ok: true } : { ok: false, error: "ذخیره‌سازی ممکن نشد" };
}
async function apiPlaylistRemove(request, env) {
  let body;
  try { body = await request.json(); } catch { return { ok: false, error: "بدنه درخواست نامعتبر است" }; }
  const user = await verifyTelegramInitData(body?.initData, env[BOT_TOKEN]);
  if (!user) return { ok: false, error: "احراز هویت نامعتبر است. لطفاً Mini App را از تلگرام دوباره باز کنید." };
  if (!Array.isArray(body?.items) || !body.items.length) return { ok: false, error: "موردی برای حذف انتخاب نشده" };
  const saved = await removeFromPlaylist(env, user.id, body.items);
  return saved ? { ok: true } : { ok: false, error: "حذف ممکن نشد" };
}
async function clearState(env, chatId) {
  const kv = env.STATE_KV;
  if (!kv) return;
  await kv.delete(`s:${chatId}`);
}

async function runSearch(env, chatId, query) {
  const r = await tmdb(env, "/search/multi", { query, include_adult: false });
  if (!r.ok) {
    await tgSend(env, chatId, `⚠️ خطا: ${escape(r.error)}`);
    return;
  }
  const raw = (r.data.results || []).filter((m) => m.media_type === "movie" || m.media_type === "tv");
  if (!raw.length) {
    await tgSend(env, chatId, "نتیجه‌ای پیدا نشد. اسم دیگری امتحان کن.");
    return;
  }
  const results = raw.slice(0, 10);
  await setState(env, chatId, { mode: "search_results", results });

  // Priority #1: the closest match, shown big with its poster.
  const top = results[0];
  const topYr = (top.release_date || top.first_air_date || "").slice(0, 4);
  const topRating = top.vote_average ? ` ⭐${top.vote_average.toFixed(1)}` : "";
  const topIcon = top.media_type === "tv" ? "📺" : "🎬";
  const topCaption = `${topIcon} <b>${escape(top.title || top.name)}</b>${topYr ? ` (${topYr})` : ""}${topRating}`;
  if (top.poster_path) {
    await fetch(`${TG(env[BOT_TOKEN])}/sendPhoto`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        photo: `${POSTER_BASE}${top.poster_path}`,
        caption: topCaption,
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [[{ text: "📋 جزئیات کامل", callback_data: `m:${top.media_type}:${top.id}` }]] },
      }),
    });
  } else {
    await tgSend(env, chatId, topCaption, detailsKeyboard([top]));
  }

  // Rest of the matches sharing the same letters, as a list underneath.
  const rest = results.slice(1);
  if (rest.length) {
    await tgSend(env, chatId,
      `🔎 نتایج مشابه دیگر برای <b>${escape(query)}</b>:\nروی فیلم مورد نظرت بزن.`,
      detailsKeyboard(rest)
    );
  }
}

// ---------- Suggestions ----------

async function emitSuggestions(env) {
  const kv = env.STATE_KV;
  const today = new Date().toISOString().slice(0, 10);
  if (kv) {
    const cached = await kv.get(`sug:${today}`);
    if (cached) return JSON.parse(cached);
  }

  // Top IMDb of all time (movie + tv) + genuinely-today's trending across
  // both media types.
  // ponytail bug found: this used to hit /movie/top_rated for "popular",
  // which is itself an all-time list and barely differs from `top` below —
  // so the KV cache was working fine, but the *source* never had anything
  // new to serve day to day. /trending/all/day is TMDB's real daily
  // trending feed (movies + tv, tagged with media_type) and actually
  // changes with each cache refresh.
  const [topMovie, topTv, trending] = await Promise.all([
    tmdb(env, "/discover/movie", { sort_by: "vote_average.desc", "vote_count.gte": 1000, page: "1" }),
    tmdb(env, "/discover/tv", { sort_by: "vote_average.desc", "vote_count.gte": 300, page: "1" }),
    tmdb(env, "/trending/all/day", {}),
  ]);
  // ponytail: trust IMDB-via-TMDB sorting rather than re-implementing IMDB calls.
  const topM = (topMovie.ok ? topMovie.data.results : []).map((m) => ({ ...m, media_type: "movie" }));
  const topT = (topTv.ok ? topTv.data.results : []).map((m) => ({ ...m, media_type: "tv" }));
  const a = topM.concat(topT).sort((x, y) => (y.vote_average || 0) - (x.vote_average || 0)).slice(0, 5);
  const b = (trending.ok ? (trending.data.results || []).filter((m) => m.media_type === "movie" || m.media_type === "tv") : []).slice(0, 5);

  const payload = { a, b };
  if (kv) await kv.put(`sug:${today}`, JSON.stringify(payload), { expirationTtl: 86400 });
  return payload;
}

async function sendSuggestions(env, chatId) {
  const { a, b } = await emitSuggestions(env);
  // ponytail: 1 message with 10 buttons beats 2 messages + 'loading...'
  await tgSend(env, chatId,
    "🏆  <b>۵ فیلم/سریال برتر TMDB</b>\n━━━━━━━━━━━━━━━━━\n" +
    "🔥  <b>۵ مورد محبوب امروز</b>\n━━━━━━━━━━━━━━━━━",
    { reply_markup: { inline_keyboard:
      a.concat(b).slice(0, 10).map((m, i) => [{
        text: `${m.media_type === "tv" ? "📺" : "🎞"}  ${i + 1}. ${(m.title || m.name).slice(0, 36)}  ⭐${m.vote_average?.toFixed(1) || "?"}`,
        callback_data: `m:${m.media_type || "movie"}:${m.id}`,
      }]).concat([[{ text: "🔙  بازگشت", callback_data: "menu:home" }]])
    } }
  );
}

// Register a chat so the daily cron can push to all starters
async function registerUser(env, chatId) {
  const kv = env.STATE_KV;
  if (!kv) return;
  await kv.put(`u:${chatId}`, "1");
}

async function pushDailyToAll(env) {
  const kv = env.STATE_KV;
  if (!kv) return 0;
  const cachedToday = await kv.get(`sug:${new Date().toISOString().slice(0, 10)}`);
  if (!cachedToday) await emitSuggestions(env);
  const list = await kv.list({ prefix: "u:" });
  let n = 0;
  for (const k of list.keys) {
    const chatId = k.name.slice(2);
    try { await sendSuggestions(env, chatId); n++; } catch {}
  }
  return n;
}

// ---------- Callback router ----------

// Shared behind both entry points: a tap on an inline-keyboard "menu:xxx"
// button (msgId/cbId present → edits the existing message) and a tap
// inside the /menu Mini App (msgId/cbId absent → sends a fresh message,
// since a Mini App closes and leaves no message of its own to edit).
async function runMenuAction(env, { chatId, mode, msgId, cbId, origin }) {
  const respond = (text, extra = {}) =>
    msgId ? tgEdit(env, chatId, msgId, text, extra) : tgSend(env, chatId, text, extra);

  if (mode === "home") {
    await setState(env, chatId, { mode: "home" });
    await respond("🏠  <b>منوی اصلی</b>\n━━━━━━━━━━━━━━━", menuHomeButton(origin));
  } else if (mode === "search") {
    await setState(env, chatId, { mode: "await_query" });
    await enterSearchMode(env, chatId, msgId);
  } else if (mode === "suggest") {
    await setState(env, chatId, { mode: "home" });
    if (cbId) await tgAnswerCb(env, cbId, "در حال بارگذاری...");
    await sendSuggestions(env, chatId);
  } else if (mode === "genres") {
    if (cbId) await tgAnswerCb(env, cbId, "...");
    const rows = (await getGenres(env)).genres.slice(0, 12);
    const inline = rows.map(g => [{
      text: `🎭 ${g.name}`,
      callback_data: `g:${g.id}:${g.name}`,
    }]).concat([[{ text: "📂  بازگشت به منو", web_app: { url: `${origin}/menu` } }]]);
    await respond("📚  <b>انتخاب ژانر</b>\n━━━━━━━━━━", { reply_markup: { inline_keyboard: inline } });
  } else if (mode === "popular") {
    const top = await mixedList(env, "/movie/popular", "/tv/popular", { page: "1" }, { page: "1" });
    await respond("🔥  <b>پرطرفدارترین‌های این لحظه</b>\n━━━━━━━━━━", detailsKeyboard(top));
  } else if (mode === "random") {
    if (cbId) await tgAnswerCb(env, cbId, "در حال انتخاب...");
    await pickRandom(env, chatId);
  } else if (mode === "now_playing") {
    const top = await mixedList(env, "/movie/now_playing", "/tv/on_the_air", { page: "1" }, { page: "1" });
    await respond("🎞  <b>در حال اکران</b>\n━━━━━━", detailsKeyboard(top));
  } else if (mode === "upcoming") {
    const today = new Date().toISOString().slice(0, 10);
    const top = await mixedList(env, "/movie/upcoming", "/discover/tv", { page: "1" },
      { page: "1", sort_by: "first_air_date.desc", "first_air_date.gte": today });
    await respond("📅  <b>به‌زودی</b>\n━━━━", detailsKeyboard(top));
  } else if (mode === "help") {
    if (cbId) await tgAnswerCb(env, cbId, "...");
    await respond(
      "❓  <b>راهنما</b>\n━━━━━━━━━\n\n" +
      "🔍  جستجو: اسم فیلم/سریال رو بفرست.\n" +
      "🏆  پیشنهادی: ۵ فیلم برتر TMDB + ۵ محبوب روز.\n" +
      "📚  ژانر: یک ژانر انتخاب کن تا بهترین‌ها نمایش داده بشن.\n\n" +
      "هر روز ساعت ۹ صبح به‌وقت تهران، پیشنهادی‌های روز به‌صورت خودکار ارسال می‌شن.",
      { reply_markup: { inline_keyboard: [[{ text: "📂  بازگشت به منو", web_app: { url: `${origin}/menu` } }]] } });
  }
}

async function onCallback(env, cb, origin) {
  const data = cb.data || "";
  const chatId = cb.message?.chat?.id;
  const msgId = cb.message?.message_id;
  if (!chatId) return;

  if (data.startsWith("menu:")) {
    const mode = data.slice(5);
    await runMenuAction(env, { chatId, mode, msgId, cbId: cb.id, origin });
    return;
  }

  if (data.startsWith("g:")) {
    // genre id + name picked → show A-Z so the user narrows by first letter
    const [, gid, gname] = data.split(":");
    await tgAnswerCb(env, cb.id, "...");
    await tgEdit(env, chatId, msgId,
      `🎭  ژانر <b>${escape(gname)}</b>\n━━━━━━━━━━\nحرف اول اسم فیلم رو انتخاب کن:`,
      { reply_markup: { inline_keyboard: buildAlphabetRows(gid) } });
    return;
  }

  if (data.startsWith("gl:")) {
    // genre id + letter picked → top movies in that genre starting with it
    const [, gid, letter] = data.split(":");
    await tgAnswerCb(env, cb.id, "در حال جستجو...");
    const movies = await findMoviesByGenreLetter(env, gid, letter);
    if (!movies.length) {
      await tgSend(env, chatId, `فیلمی با حرف <b>${letter}</b> در این ژانر پیدا نشد.`, { parse_mode: "HTML" });
      return;
    }
    await tgSend(env, chatId, `🎭  فیلم‌های این ژانر با حرف <b>${letter}</b>:`,
      detailsKeyboard(movies));
    return;
  }

  if (data.startsWith("m:")) {
    const [, type, id] = data.split(":");
    await tgAnswerCb(env, cb.id, "در حال بارگذاری جزئیات...");
    await sendMovieDetails(env, chatId, id, type);
  }
}

async function sendMovieDetails(env, chatId, id, type = "movie") {
  const raw = await getFullDetails(id, env, type);
  if (!raw) {
    await tgSend(env, chatId, "⚠️ خطا در دریافت جزئیات.");
    return;
  }
  const d = raw;
  const subs = await findSubtitles(d.title, d.year);
  await tgSend(env, chatId, fmtDetails(d));
  if (d.poster) await tgSend(env, chatId, d.poster);
  await tgSend(env, chatId, fmtSubtitleLinks(subs));
}

async function pickRandom(env, chatId) {
  const type = Math.random() < 0.6 ? "movie" : "tv";
  const page = 1 + Math.floor(Math.random() * 10);
  const path = type === "movie" ? "/discover/movie" : "/discover/tv";
  const r = await tmdb(env, path, {
    sort_by: "popularity.desc", "vote_count.gte": type === "movie" ? 200 : 100, page: String(page),
  });
  const pool = (r.ok ? r.data.results : []).filter(Boolean);
  if (!pool.length) { await tgSend(env, chatId, "⚠️ خطا در پیشنهاد تصادفی."); return; }
  const pick = pool[Math.floor(Math.random() * pool.length)];
  const raw = await getFullDetails(pick.id, env, type);
  if (!raw) { await tgSend(env, chatId, "⚠️ خطا در دریافت جزئیات."); return; }
  const d = raw;
  await tgSend(env, chatId, `🎲 <b>پیشنهاد تصادفی</b>\n━━━━━━━`);
  await tgSend(env, chatId, fmtDetails(d));
  if (d.poster) await tgSend(env, chatId, d.poster);
}

function assistantHtml() {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>فیلم‌یاب — دستیار جستجوی فیلم</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;700;900&display=swap" rel="stylesheet">
<style>
  :root{
    --bg: #0D0B0E;
    --panel-solid: #1A1613;
    --gold: #C9A227;
    --gold-dim: #8A6E1E;
    --velvet: #6E1423;
    --cream: #EDE6DA;
    --muted: #8C8478;
    --line: #2E2822;
  }
  *{box-sizing:border-box;}
  html,body{ margin:0; padding:0; height:100%; background:var(--bg); color:var(--cream); font-family:'Vazirmatn',sans-serif; }
  body{ display:flex; flex-direction:column; height:100vh; overflow:hidden; }

  .reel-strip{
    height:14px; width:100%; flex-shrink:0; background-color:#000;
    background-image: radial-gradient(circle, var(--bg) 3.5px, var(--gold-dim) 4px, var(--gold-dim) 4.5px, transparent 5px);
    background-size: 26px 14px;
  }

  header{
    flex-shrink:0; padding:16px 24px 12px;
    background: linear-gradient(180deg,#14100E 0%,#0D0B0E 100%);
    border-bottom:1px solid var(--line);
    display:flex; align-items:center; justify-content:space-between; gap:14px;
  }
  header .left{ display:flex; align-items:center; gap:12px; }
  header svg{ width:36px; height:36px; flex-shrink:0; }
  header h1{ font-size:18px; font-weight:900; margin:0; color:var(--gold); }
  header p{ margin:2px 0 0; font-size:12px; color:var(--muted); }
  .status{ font-size:11px; color:var(--muted); display:flex; align-items:center; gap:6px; }
  .dot{ width:7px; height:7px; border-radius:50%; background:#5aa06a; flex-shrink:0; }
  .dot.off{ background:#a05a5a; }

  #chat{ flex:1; overflow-y:auto; padding:20px 14px; display:flex; flex-direction:column; gap:12px; max-width:820px; width:100%; margin:0 auto; }
  #chat::-webkit-scrollbar{ width:8px; }
  #chat::-webkit-scrollbar-thumb{ background:var(--line); border-radius:4px; }

  .msg{ max-width:88%; padding:11px 15px; border-radius:14px; font-size:14px; line-height:1.9; }
  .msg.user{ align-self:flex-start; background:var(--velvet); color:var(--cream); border-bottom-left-radius:3px; }
  .msg.bot{ align-self:flex-end; background:var(--panel-solid); border:1px solid var(--line); color:var(--cream); border-bottom-right-radius:3px; }

  .welcome{ align-self:center; text-align:center; color:var(--muted); font-size:13px; padding:26px 20px; max-width:520px; line-height:2; }
  .row{ display:flex; gap:8px; flex-wrap:wrap; justify-content:center; margin-top:14px; }
  .chip{ border:1px solid var(--line); color:var(--gold); background:transparent; padding:7px 13px; border-radius:20px; font-size:12.5px; cursor:pointer; font-family:inherit; }
  .chip:hover{ border-color:var(--gold-dim); background:#1F1A16; }

  .dots{ display:flex; gap:5px; }
  .dots span{ width:6px; height:6px; border-radius:50%; background:var(--gold-dim); animation:blink 1.2s infinite ease-in-out; }
  .dots span:nth-child(2){ animation-delay:.2s; }
  .dots span:nth-child(3){ animation-delay:.4s; }
  @keyframes blink{ 0%,80%,100%{opacity:.25;} 40%{opacity:1;} }

  .grid-posters{ display:grid; grid-template-columns:repeat(auto-fill,minmax(104px,1fr)); gap:8px; margin-top:8px; }
  .pcard{ width:100%; max-width:150px; margin:0 auto; cursor:pointer; border-radius:8px; overflow:hidden; background:#0000002b; border:1px solid var(--line); }
  .pcard img{ width:100%; aspect-ratio:2/3; object-fit:cover; display:block; background:#201c18; }
  .ph{ width:100%; aspect-ratio:2/3; display:flex; align-items:center; justify-content:center; font-size:22px; background:#201c18; }
  .pt{ font-size:11.5px; padding:5px 6px 2px; line-height:1.4; }
  .pr{ font-size:11px; color:var(--gold); padding:0 6px 6px; }

  .topcard{ display:flex; gap:12px; margin-bottom:6px; }
  .topcard img{ width:84px; height:126px; border-radius:8px; object-fit:cover; flex-shrink:0; }
  .topcard .ph{ width:84px; height:126px; border-radius:8px; flex-shrink:0; }
  .badge{ display:inline-block; font-size:10.5px; color:#412402; background:var(--gold); padding:2px 8px; border-radius:10px; margin-bottom:4px; }
  .ov{ font-size:12.5px; color:var(--muted); margin-top:4px; }
  .sectitle{ font-size:12.5px; color:var(--gold); margin:12px 0 4px; font-weight:700; }

  .detail-poster{ width:120px; border-radius:8px; float:left; margin:0 0 8px 12px; }
  .dt{ font-size:16px; font-weight:700; color:var(--gold); }
  .dy{ font-size:12px; color:var(--muted); margin-bottom:6px; }
  .kv{ font-size:12.5px; margin:3px 0; }
  .kv b{ color:var(--gold); font-weight:700; }
  .clearfix::after{ content:""; display:table; clear:both; }
  .sublinks a{ display:block; font-size:12px; color:#7fb3d5; margin:3px 0; word-break:break-all; }

  .letters{ display:flex; flex-wrap:wrap; gap:6px; margin-top:6px; }
  .letters div{ width:30px; height:30px; display:flex; align-items:center; justify-content:center; border:1px solid var(--line); border-radius:6px; cursor:pointer; font-size:13px; }
  .letters div:hover{ border-color:var(--gold-dim); background:#1F1A16; }

  .err{ color:#e08484; font-size:13px; }

  form{ flex-shrink:0; display:flex; gap:10px; padding:12px 16px 16px; max-width:820px; width:100%; margin:0 auto; border-top:1px solid var(--line); }
  textarea{ flex:1; resize:none; background:var(--panel-solid); border:1px solid var(--line); color:var(--cream); border-radius:12px; padding:11px 14px; font-family:inherit; font-size:14.5px; line-height:1.6; max-height:110px; outline:none; }
  textarea:focus{ border-color:var(--gold-dim); }
  textarea::placeholder{ color:var(--muted); }
  button.send{ flex-shrink:0; width:48px; height:48px; border-radius:12px; border:none; background:var(--gold); color:#171310; font-size:18px; cursor:pointer; font-weight:700; align-self:flex-end; }
  button.send:disabled{ opacity:.5; cursor:default; }
</style>
</head>
<body>

<div class="reel-strip"></div>

<header>
  <div class="left">
    <svg viewBox="0 0 48 48" fill="none">
      <rect x="4" y="16" width="40" height="28" rx="3" fill="#1A1613" stroke="#C9A227" stroke-width="2"/>
      <path d="M4 16 L44 16 L41 6 L7 9 Z" fill="#1A1613" stroke="#C9A227" stroke-width="2" stroke-linejoin="round"/>
      <path d="M9 8.5 L16 15.5 M17 7.3 L24 14.5 M25 6.5 L32 13.5 M33 6 L40 13" stroke="#C9A227" stroke-width="2"/>
    </svg>
    <div>
      <h1>فیلم‌یاب</h1>
      <p>دستیار جستجوی فیلم و سریال — بدون هوش مصنوعی، مستقیم از دیتابیس شما</p>
    </div>
  </div>
  <div class="status"><span class="dot" id="statusDot"></span><span id="statusText">در حال بررسی اتصال...</span></div>
</header>

<div id="chat">
  <div class="welcome" id="welcome">
    اسم هر فیلم یا سریالی رو بنویس تا جستجو کنم، یا از دکمه‌های زیر استفاده کن.
    <div class="row">
      <button class="chip" data-q="پیشنهادی امروز">پیشنهادی امروز</button>
      <button class="chip" data-q="پرطرفدارها">پرطرفدارها</button>
      <button class="chip" data-q="در حال اکران">در حال اکران</button>
      <button class="chip" data-q="یک فیلم تصادفی">تصادفی</button>
      <button class="chip" data-q="ژانرها">فهرست ژانرها</button>
      <button class="chip" data-q="راهنما">راهنما</button>
    </div>
  </div>
</div>

<form id="form">
  <textarea id="input" rows="1" placeholder="مثلا: Inception یا «پیشنهاد بده»"></textarea>
  <button class="send" id="sendBtn" type="submit">↑</button>
</form>

<script>
const WORKER_BASE = "";

const chat = document.getElementById('chat');
const form = document.getElementById('form');
const input = document.getElementById('input');
const sendBtn = document.getElementById('sendBtn');
const welcome = document.getElementById('welcome');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');

function esc(s){
  return (s || '').toString()
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function autoGrow(){ input.style.height='auto'; input.style.height=Math.min(input.scrollHeight,110)+'px'; }
input.addEventListener('input', autoGrow);

function addUserBubble(text){
  if(welcome) welcome.remove();
  const div = document.createElement('div');
  div.className='msg user';
  div.textContent = text;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

function addBotBubble(html){
  const div = document.createElement('div');
  div.className='msg bot';
  div.innerHTML = html;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
  return div;
}

function loadingDots(){
  return '<div class="dots"><span></span><span></span><span></span></div>';
}

async function apiGet(path){
  const res = await fetch(path);
  if(!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}

async function checkConnection(){
  try{
    const r = await fetch('/');
    if(r.ok){ statusDot.classList.remove('off'); statusText.textContent='متصل به سرور شما'; }
    else throw new Error();
  }catch(e){
    statusDot.classList.add('off');
    statusText.textContent='عدم اتصال به Worker';
  }
}
checkConnection();

function posterGrid(items){
  if(!items || !items.length) return '';
  return '<div class="grid-posters">' + items.map(function(m){
    const isTv = m.type === 'tv';
    const thumb = m.poster
      ? '<img src="'+esc(m.poster)+'">'
      : '<div class="ph">'+(isTv ? '📺' : '🎬')+'</div>';
    return '<div class="pcard" data-movie-id="'+m.id+'" data-type="'+(m.type||'movie')+'">'+thumb+
      '<div class="pt">'+(isTv ? '📺 ' : '')+esc(m.title)+(m.year?(' ('+m.year+')'):'')+'</div>'+
      (m.rating ? '<div class="pr">⭐ '+m.rating+'</div>' : '') +
      '</div>';
  }).join('') + '</div>';
}

async function runAction(fetchFn, renderFn){
  const bubble = addBotBubble(loadingDots());
  try{
    const res = await fetchFn();
    bubble.innerHTML = renderFn(res);
  }catch(e){
    bubble.innerHTML = '<div class="err">ارتباط با سرور برقرار نشد. مطمئن شو Worker روشن و آدرسش درسته.</div>';
  }
  chat.scrollTop = chat.scrollHeight;
}

function renderSearch(res, query){
  if(!res.ok) return '<div class="err">خطا: '+esc(res.error)+'</div>';
  if(!res.top) return 'برای «'+esc(query)+'» نتیجه‌ای پیدا نشد.';
  const t = res.top;
  const tIsTv = t.type === 'tv';
  const thumb = t.poster ? '<img src="'+esc(t.poster)+'">' : '<div class="ph">'+(tIsTv?'📺':'🎬')+'</div>';
  let html = '<div class="topcard">'+thumb+
    '<div><span class="badge">بهترین تطابق</span>'+
    '<div class="dt">'+(tIsTv?'📺 ':'')+esc(t.title)+(t.year?(' ('+t.year+')'):'')+'</div>'+
    (t.rating ? '<div class="dy">⭐ '+t.rating+'</div>' : '')+
    (t.overview ? '<div class="ov">'+esc(t.overview.slice(0,180))+(t.overview.length>180?'…':'')+'</div>' : '')+
    '</div></div>';
  if(res.others && res.others.length){
    html += '<div class="sectitle">موارد مشابه</div>' + posterGrid(res.others);
  }
  return html;
}

function renderDetail(res){
  if(!res.ok) return '<div class="err">خطا: '+esc(res.error)+'</div>';
  const d = res.detail;
  const isTv = d.type === 'tv';
  const subs = res.subtitles || { filmo:[], subtitlecat:[] };
  let html = '<div class="clearfix">';
  if(d.poster) html += '<img class="detail-poster" src="'+esc(d.poster)+'">';
  html += '<div class="dt">'+(isTv?'📺 ':'')+esc(d.title)+'</div>';
  html += '<div class="dy">'+esc(d.year||'')+'</div>';
  html += '<div class="kv"><b>امتیاز:</b> '+esc(d.rating||'—')+'/10 ('+esc(d.votes||0)+' رای)</div>';
  html += isTv
    ? '<div class="kv"><b>فصل‌ها:</b> '+esc(d.seasons||'?')+' فصل · '+esc(d.episodes||'?')+' قسمت</div>'
    : '<div class="kv"><b>مدت:</b> '+esc(d.runtime||'?')+' دقیقه</div>';
  if(d.genres) html += '<div class="kv"><b>ژانر:</b> '+esc(d.genres)+'</div>';
  if(d.directors) html += '<div class="kv"><b>'+(isTv?'سازنده':'کارگردان')+':</b> '+esc(d.directors)+'</div>';
  if(d.cast) html += '<div class="kv"><b>بازیگران:</b> '+esc(d.cast)+'</div>';
  html += '</div>';
  if(d.overview) html += '<div class="ov" style="margin-top:6px">'+esc(d.overview)+'</div>';
  const links = (subs.filmo||[]).concat(subs.subtitlecat||[]);
  if(links.length){
    html += '<div class="sectitle">زیرنویس فارسی</div><div class="sublinks">' +
      links.map(function(u){ return '<a href="'+esc(u)+'" target="_blank" rel="noopener">'+esc(u)+'</a>'; }).join('') +
      '</div>';
  }
  html += '<div class="sectitle">دانلود فیلم/سریال</div><div class="sublinks"><a href="https://filmo.ir" target="_blank" rel="noopener">📦 filmo.ir</a><a href="https://subf2m.co" target="_blank" rel="noopener">📦 subf2m.co</a></div>';
  html += '<div style="text-align:center;color:var(--muted);font-size:11.5px;margin-top:4px;">برای دانلود این فیلم/سریال می‌توانید از طریق این دو سایت اقدام کنید</div>';
  return html;
}

function renderSuggestions(res){
  if(!res.ok) return '<div class="err">خطا: '+esc(res.error)+'</div>';
  let html = '<div class="sectitle">🏆 برترین‌های TMDB</div>' + posterGrid(res.top);
  html += '<div class="sectitle">🔥 محبوب‌ترین روز</div>' + posterGrid(res.popular);
  return html;
}

function renderSimpleList(res, emptyLabel){
  if(!res.ok) return '<div class="err">خطا: '+esc(res.error)+'</div>';
  if(!res.results || !res.results.length) return emptyLabel;
  return posterGrid(res.results);
}

function renderGenres(res){
  if(!res.ok || !res.genres.length) return '<div class="err">خطا در دریافت ژانرها.</div>';
  return '<div class="row" style="justify-content:flex-start">' + res.genres.map(function(g){
    return '<button type="button" class="chip" data-genre-id="'+g.id+'" data-genre-name="'+esc(g.name)+'">'+esc(g.name)+'</button>';
  }).join('') + '</div>';
}

function renderLetters(gid, gname){
  const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
  return '<div class="ov">حرف اول اسم فیلم توی ژانر «'+esc(gname)+'» رو انتخاب کن:</div><div class="letters">' +
    letters.map(function(l){ return '<div data-letter-pick data-gid="'+gid+'" data-gname="'+esc(gname)+'" data-letter="'+l+'">'+l+'</div>'; }).join('') +
    '</div>';
}

function helpText(){
  return 'می‌تونی این‌طوری باهام حرف بزنی:<br>' +
    '🔍 اسم فیلم یا سریال رو مستقیم بنویس (مثلا: Interstellar)<br>' +
    '🏆 بنویس «پیشنهادی امروز» یا «پیشنهاد بده»<br>' +
    '🔥 بنویس «پرطرفدارها» یا «محبوب‌ترین‌ها»<br>' +
    '🎞 بنویس «در حال اکران»<br>' +
    '📅 بنویس «به‌زودی» یا «اکران آینده»<br>' +
    '🎲 بنویس «تصادفی» یا «یک فیلم پیشنهاد بده»<br>' +
    '🎭 بنویس «ژانرها» یا «فهرست ژانر»<br>' +
    'روی هر پوستر یا کارت هم بزن تا جزئیات کامل + لینک زیرنویس فارسی رو ببینی.';
}

function detectIntent(text){
  const t = text.trim();
  if(/راهنما|کمک|help/i.test(t)) return {type:'help'};
  if(/تصادف/i.test(t)) return {type:'random'};
  if(/پیشنهاد/i.test(t)) return {type:'suggestions'};
  if(/پرطرفدار|محبوب/i.test(t)) return {type:'popular'};
  if(/به[\s‌]?زودی|اکران آینده|upcoming/i.test(t)) return {type:'upcoming'};
  if(/در حال اکران|اکران(?! آینده)/i.test(t)) return {type:'now_playing'};
  if(/ژانر/i.test(t)) return {type:'genres'};
  return {type:'search', query:t};
}

function dispatch(intent){
  if(intent.type === 'help'){
    addBotBubble(helpText());
  } else if(intent.type === 'random'){
    runAction(function(){ return apiGet('/api/random'); }, renderDetail);
  } else if(intent.type === 'suggestions'){
    runAction(function(){ return apiGet('/api/suggestions'); }, renderSuggestions);
  } else if(intent.type === 'popular'){
    runAction(function(){ return apiGet('/api/popular'); }, function(r){ return renderSimpleList(r,'موردی پیدا نشد.'); });
  } else if(intent.type === 'now_playing'){
    runAction(function(){ return apiGet('/api/now_playing'); }, function(r){ return renderSimpleList(r,'موردی پیدا نشد.'); });
  } else if(intent.type === 'upcoming'){
    runAction(function(){ return apiGet('/api/upcoming'); }, function(r){ return renderSimpleList(r,'موردی پیدا نشد.'); });
  } else if(intent.type === 'genres'){
    runAction(function(){ return apiGet('/api/genres'); }, renderGenres);
  } else if(intent.type === 'search'){
    runAction(function(){ return apiGet('/api/search?q=' + encodeURIComponent(intent.query)); }, function(r){ return renderSearch(r, intent.query); });
  }
}

function sendMessage(text){
  if(!text.trim()) return;
  addUserBubble(text);
  input.value=''; autoGrow();
  dispatch(detectIntent(text));
}

form.addEventListener('submit', function(e){ e.preventDefault(); sendMessage(input.value); });
input.addEventListener('keydown', function(e){
  if(e.key==='Enter' && !e.shiftKey){ e.preventDefault(); form.requestSubmit(); }
});

chat.addEventListener('click', function(e){
  const movieEl = e.target.closest('[data-movie-id]');
  if(movieEl){
    const t = movieEl.dataset.type || 'movie';
    runAction(function(){ return apiGet('/api/movie?id=' + encodeURIComponent(movieEl.dataset.movieId) + '&type=' + encodeURIComponent(t)); }, renderDetail);
    return;
  }
  const genreEl = e.target.closest('[data-genre-id]');
  if(genreEl){
    addBotBubble(renderLetters(genreEl.dataset.genreId, genreEl.dataset.genreName));
    return;
  }
  const letterEl = e.target.closest('[data-letter-pick]');
  if(letterEl){
    const gid = letterEl.dataset.gid, gname = letterEl.dataset.gname, letter = letterEl.dataset.letter;
    runAction(function(){ return apiGet('/api/genre-letter?gid='+encodeURIComponent(gid)+'&letter='+encodeURIComponent(letter)); },
      function(r){ return renderSimpleList(r, 'فیلمی با حرف '+letter+' در این ژانر پیدا نشد.'); });
    return;
  }
  const chipQ = e.target.closest('.chip[data-q]');
  if(chipQ){ sendMessage(chipQ.dataset.q); return; }
});
</script>

</body>
</html>
`;
}

function assistantAiHtml() {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>دستیار هوش مصنوعی سینما</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;700;900&display=swap" rel="stylesheet">
<style>
  :root{
    --bg: #0D0B0E; --panel-solid: #1A1613; --gold: #C9A227; --gold-dim: #8A6E1E;
    --velvet: #6E1423; --cream: #EDE6DA; --muted: #8C8478; --line: #2E2822;
  }
  *{box-sizing:border-box;}
  html,body{ margin:0; padding:0; height:100%; background:var(--bg); color:var(--cream); font-family:'Vazirmatn',sans-serif; }
  body{ display:flex; flex-direction:column; height:100vh; overflow:hidden; }
  .reel-strip{ height:14px; width:100%; flex-shrink:0; background-color:#000;
    background-image: radial-gradient(circle, var(--bg) 3.5px, var(--gold-dim) 4px, var(--gold-dim) 4.5px, transparent 5px);
    background-size: 26px 14px; }
  header{ flex-shrink:0; padding:16px 24px 12px; background: linear-gradient(180deg,#14100E 0%,#0D0B0E 100%);
    border-bottom:1px solid var(--line); display:flex; align-items:center; gap:12px; }
  header a.back{ color:var(--muted); text-decoration:none; font-size:20px; padding:4px 6px; }
  header h1{ font-size:18px; font-weight:900; margin:0; color:var(--gold); }
  header p{ margin:2px 0 0; font-size:12px; color:var(--muted); }

  #chat{ flex:1; overflow-y:auto; padding:20px 14px; display:flex; flex-direction:column; gap:12px; max-width:760px; width:100%; margin:0 auto; }
  #chat::-webkit-scrollbar{ width:8px; }
  #chat::-webkit-scrollbar-thumb{ background:var(--line); border-radius:4px; }
  .msg{ max-width:85%; padding:11px 15px; border-radius:14px; font-size:14.5px; line-height:1.9; white-space:pre-wrap; word-wrap:break-word; }
  .msg.user{ align-self:flex-start; background:var(--velvet); color:var(--cream); border-bottom-left-radius:3px; }
  .msg.bot{ align-self:flex-end; background:var(--panel-solid); border:1px solid var(--line); color:var(--cream); border-bottom-right-radius:3px; }
  .welcome{ align-self:center; text-align:center; color:var(--muted); font-size:13px; padding:26px 20px; max-width:480px; line-height:2; }
  .row{ display:flex; gap:8px; flex-wrap:wrap; justify-content:center; margin-top:14px; }
  .chip{ border:1px solid var(--line); color:var(--gold); background:transparent; padding:7px 13px; border-radius:20px; font-size:12.5px; cursor:pointer; font-family:inherit; }
  .chip:hover{ border-color:var(--gold-dim); background:#1F1A16; }
  .typing{ align-self:flex-end; display:flex; gap:5px; padding:12px 16px; background:var(--panel-solid); border:1px solid var(--line); border-radius:14px; border-bottom-right-radius:3px; }
  .typing span{ width:6px; height:6px; border-radius:50%; background:var(--gold-dim); animation:blink 1.2s infinite ease-in-out; }
  .typing span:nth-child(2){ animation-delay:.2s; }
  .typing span:nth-child(3){ animation-delay:.4s; }
  @keyframes blink{ 0%,80%,100%{opacity:.25;} 40%{opacity:1;} }

  form{ flex-shrink:0; display:flex; gap:10px; padding:14px 16px 18px; max-width:760px; width:100%; margin:0 auto; border-top:1px solid var(--line); }
  textarea{ flex:1; resize:none; background:var(--panel-solid); border:1px solid var(--line); color:var(--cream); border-radius:12px; padding:11px 14px; font-family:inherit; font-size:14.5px; line-height:1.6; max-height:120px; outline:none; }
  textarea:focus{ border-color:var(--gold-dim); }
  textarea::placeholder{ color:var(--muted); }
  button.send{ flex-shrink:0; width:48px; height:48px; border-radius:12px; border:none; background:var(--gold); color:#171310; font-size:18px; cursor:pointer; font-weight:700; align-self:flex-end; }
  button.send:disabled{ opacity:.5; cursor:default; }
</style>
</head>
<body>

<div class="reel-strip"></div>

<header>
  <a class="back" href="/menu" aria-label="بازگشت">→</a>
  <div>
    <h1>دستیار هوش مصنوعی سینما</h1>
    <p>مدل هوش مصنوعی اختصاصی — گفتگوی آزاد درباره فیلم و سریال</p>
  </div>
</header>

<div id="chat">
  <div class="welcome" id="welcome">
    هر سوالی درباره فیلم، سریال، کارگردان یا بازیگر داری بپرس.
    <div class="row">
      <button class="chip" data-q="بهترین سریال‌های جنایی-روانشناختی ده سال اخیر رو معرفی کن">سریال جنایی خوب</button>
      <button class="chip" data-q="فیلم‌های کریستوفر نولان رو رتبه‌بندی کن">فیلم‌های نولان</button>
      <button class="chip" data-q="یک فیلم مشابه Inception پیشنهاد بده">مشابه Inception</button>
    </div>
  </div>
</div>

<form id="form">
  <textarea id="input" rows="1" placeholder="مثلا: بهترین فیلم‌های کیارستمی کدوماند؟"></textarea>
  <button class="send" id="sendBtn" type="submit">↑</button>
</form>

<script>
const chat = document.getElementById('chat');
const form = document.getElementById('form');
const input = document.getElementById('input');
const sendBtn = document.getElementById('sendBtn');
const welcome = document.getElementById('welcome');
let history = [];

function autoGrow(){ input.style.height='auto'; input.style.height=Math.min(input.scrollHeight,120)+'px'; }
input.addEventListener('input', autoGrow);

function addMessage(text, role){
  if(welcome) welcome.remove();
  const div = document.createElement('div');
  div.className = 'msg ' + (role==='user' ? 'user' : 'bot');
  div.textContent = text;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
  return div;
}
function showTyping(){
  const div = document.createElement('div');
  div.className='typing'; div.id='typingIndicator';
  div.innerHTML='<span></span><span></span><span></span>';
  chat.appendChild(div); chat.scrollTop = chat.scrollHeight;
}
function hideTyping(){ const el=document.getElementById('typingIndicator'); if(el) el.remove(); }

async function sendMessage(text){
  if(!text.trim()) return;
  addMessage(text,'user');
  history.push({ role:'user', content:text });
  input.value=''; autoGrow();
  sendBtn.disabled = true;
  showTyping();
  try{
    const res = await fetch('/api/ai', {
      method:'POST',
      headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify({ messages: history }),
    });
    const data = await res.json();
    hideTyping();
    if(data.ok){
      addMessage(data.reply,'bot');
      history.push({ role:'assistant', content:data.reply });
    } else {
      addMessage('خطا: ' + (data.error || 'پاسخی دریافت نشد.'), 'bot');
    }
  }catch(e){
    hideTyping();
    addMessage('ارتباط با سرور برقرار نشد.', 'bot');
  }finally{
    sendBtn.disabled = false;
  }
}

form.addEventListener('submit', function(e){ e.preventDefault(); sendMessage(input.value); });
input.addEventListener('keydown', function(e){
  if(e.key==='Enter' && !e.shiftKey){ e.preventDefault(); form.requestSubmit(); }
});
document.querySelectorAll('.chip').forEach(function(chip){
  chip.addEventListener('click', function(){ sendMessage(chip.dataset.q); });
});
</script>

</body>
</html>
`;
}

// ---------- Mini App JSON API ----------
// Everything the /menu web page needs, so it can be a real app (search with
// posters, genre → A-Z → results, movie detail, subtitles) instead of just a
// button launcher that hands actions back to the chat.

function apiJson(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      // Lets an external front-end (e.g. the standalone assistant page)
      // call these endpoints directly from a different origin.
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}

async function apiSearch(env, query) {
  if (!query || query.trim().length < 2) return { ok: true, top: null, others: [] };
  const r = await tmdb(env, "/search/multi", { query: query.trim(), include_adult: "false" });
  if (!r.ok) return { ok: false, error: r.error };
  const raw = (r.data.results || []).filter((m) => m.media_type === "movie" || m.media_type === "tv");
  const results = raw.slice(0, 15).map((m) => mapItem(m, m.media_type));
  // Priority #1: closest match with its poster. Priority #2+: the rest of
  // the titles TMDB matched against the same letters.
  const [top, ...others] = results;
  return { ok: true, top: top || null, others };
}

async function apiGenres(env) {
  return await getGenres(env);
}

async function apiGenreLetter(env, gid, letter) {
  const items = await findMoviesByGenreLetter(env, gid, letter.toUpperCase());
  return { ok: true, results: items.map((m) => mapItem(m, m.media_type)) };
}

async function apiMovie(id, type, env) {
  const raw = await getFullDetails(id, env, type || "movie");
  if (!raw) return { ok: false, error: "not found" };
  const [d, subs] = await Promise.all([
    env.AI ? dFa(env, raw) : Promise.resolve(raw),
    findSubtitles(raw.title, raw.year),
  ]);
  return { ok: true, detail: d, subtitles: fmtSubtitleLinksApi(subs) };
}

function fmtSubtitleLinksApi({ catLinks, filmoLinks }) {
  return { filmo: filmoLinks.slice(0, 5), subtitlecat: catLinks.slice(0, 3) };
}

async function apiMixedList(env, moviePath, tvPath, movieParams, tvParams) {
  const items = await mixedList(env, moviePath, tvPath, movieParams, tvParams);
  return { ok: true, results: items.map((m) => mapItem(m, m.media_type)) };
}

async function apiRandom(env) {
  const type = Math.random() < 0.6 ? "movie" : "tv";
  const page = 1 + Math.floor(Math.random() * 10);
  const path = type === "movie" ? "/discover/movie" : "/discover/tv";
  const r = await tmdb(env, path, { sort_by: "popularity.desc", "vote_count.gte": type === "movie" ? 200 : 100, page: String(page) });
  const pool = (r.ok ? r.data.results : []).filter(Boolean);
  if (!pool.length) return { ok: false, error: "no results" };
  const pick = pool[Math.floor(Math.random() * pool.length)];
  return apiMovie(pick.id, type, env);
}

async function apiSuggestions(env) {
  const { a, b } = await emitSuggestions(env);
  return { ok: true, top: a.map((m) => mapItem(m, m.media_type)), popular: b.map((m) => mapItem(m, m.media_type)) };
}

async function apiFullList(env, kind) {
  const items = await fetchFullList(env, kind, 50);
  return { ok: true, results: items.map((m) => mapItem(m, m.media_type)) };
}

// System prompt for the AI option in the Mini App. Kept server-side so it
// can't be edited or read out of the client bundle.
const MOVIE_AI_SYSTEM_PROMPT = `تو یک منتقد و کارشناس حرفه‌ای سینما و سریال با دانش عمیق و به‌روز هستی. قوانین پاسخ‌دهی:

1. فقط و فقط درباره فیلم، سریال، سینما، کارگردانان، بازیگران، ژانرها، جوایز سینمایی و صنعت نمایش پاسخ بده. اگر سوال کاملا خارج از این حوزه بود، مودبانه بگو که فقط در حوزه فیلم و سریال تخصص داری.
2. پاسخ‌ها باید دقیق، فشرده و تخصصی باشند: نام دقیق اثر، سال ساخت، کارگردان، بازیگران کلیدی، ژانر، و در صورت مرتبط بودن امتیاز یا جایگاه اثر را ذکر کن.
3. از اسپویل کردن نقاط عطف داستانی یا پایان‌بندی خودداری کن مگر کاربر صریحا درخواست اسپویل کند؛ در آن صورت قبل از افشا هشدار بده.
4. وقتی توصیه فیلم/سریال می‌دهی، حداکثر ۳ تا ۵ مورد بده، هرکدام با یک جمله کوتاه درباره چرایی پیشنهاد.
5. اگر از چیزی مطمئن نیستی، صادقانه بگو مطمئن نیستی به‌جای حدس زدن.
6. پاسخ رو به فارسی روان و طبیعی بنویس مگراینکه کاربر به زبان دیگری بنویسد.
7. مختصر و متمرکز باش؛ از مقدمه‌چینی غیرضروری پرهیز کن.`;

// Cloudflare Workers AI — runs on the `env.AI` binding, no external API key
// or secret needed. Uses an instruction-tuned Llama model in non-streaming
// chat mode (messages array is supported directly by env.AI.run).
const WORKERS_AI_MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";

async function apiAi(request, env) {
  if (!env.AI) return { ok: false, error: "Workers AI باینِد نشده (AI binding رو در wrangler.toml اضافه کن)" };

  let body;
  try { body = await request.json(); } catch { return { ok: false, error: "بدنه درخواست نامعتبر است" }; }
  const messages = Array.isArray(body?.messages) ? body.messages : [];
  if (!messages.length) return { ok: false, error: "پیامی ارسال نشده" };

  const chatMessages = [{ role: "system", content: MOVIE_AI_SYSTEM_PROMPT }, ...messages];

  try {
    const result = await Promise.race([
      env.AI.run(WORKERS_AI_MODEL, { messages: chatMessages, max_tokens: 800 }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 25000)),
    ]);
    const reply = (result?.response || "").trim();
    if (!reply) return { ok: false, error: "پاسخی از مدل دریافت نشد." };
    return { ok: true, reply };
  } catch (e) {
    return { ok: false, error: e?.message === "timeout" ? "مدل هوش مصنوعی خیلی طول کشید (timeout)" : `Workers AI error: ${e?.message || e}` };
  }
}

async function handleApi(request, env, pathname) {
  try {
    const url = new URL(request.url);
    const p = url.searchParams;
    if (pathname === "/api/search") return apiJson(await apiSearch(env, p.get("q") || ""));
    if (pathname === "/api/genres") return apiJson(await apiGenres(env));
    if (pathname === "/api/genre-letter") return apiJson(await apiGenreLetter(env, p.get("gid"), p.get("letter") || "A"));
    if (pathname === "/api/movie") return apiJson(await apiMovie(p.get("id"), p.get("type"), env));
    if (pathname === "/api/popular") return apiJson(await apiMixedList(env, "/movie/popular", "/tv/popular", { page: "1" }, { page: "1" }));
    if (pathname === "/api/now_playing") return apiJson(await apiMixedList(env, "/movie/now_playing", "/tv/on_the_air", { page: "1" }, { page: "1" }));
    if (pathname === "/api/upcoming") {
      const today = new Date().toISOString().slice(0, 10);
      return apiJson(await apiMixedList(env, "/movie/upcoming", "/discover/tv", { page: "1" },
        { page: "1", sort_by: "first_air_date.desc", "first_air_date.gte": today }));
    }
    if (pathname === "/api/random") return apiJson(await apiRandom(env));
    if (pathname === "/api/suggestions") return apiJson(await apiSuggestions(env));
    if (pathname === "/api/full-list") return apiJson(await apiFullList(env, p.get("kind") || ""));
    if (pathname === "/api/ai" && request.method === "POST") return apiJson(await apiAi(request, env));
    if (pathname === "/api/playlist" && request.method === "POST") return apiJson(await apiPlaylistAdd(request, env));
    if (pathname === "/api/playlist-remove" && request.method === "POST") return apiJson(await apiPlaylistRemove(request, env));
    if (pathname === "/api/playlist") return apiJson(await apiPlaylist(request, env, url));
    return apiJson({ ok: false, error: "not found" }, 404);
  } catch (e) {
    // Whatever happens, the Mini App must always get back valid JSON —
    // an uncaught throw here would 500 the whole response and the app
    // would show a blank screen with no clue why.
    return apiJson({ ok: false, error: `internal: ${e?.message || e}` }, 200);
  }
}

// ---------- Update handler ----------

async function handleUpdate(update, env, origin) {
  if (!update) return;

  if (update.callback_query) {
    await onCallback(env, update.callback_query, origin);
    return;
  }

  if (update.inline_query) {
    await onInlineQuery(env, update.inline_query);
    return;
  }

  const msg = update.message;
  if (!msg) return;

  const chatId = msg.chat.id;

  if (msg.web_app_data) {
    // A button was tapped inside the /menu Mini App.
    let payload = null;
    try { payload = JSON.parse(msg.web_app_data.data); } catch { payload = null; }
    if (payload?.action === "movie" && payload.id) {
      await sendMovieDetails(env, chatId, payload.id, payload.type || "movie");
    } else if (payload?.action) {
      await runMenuAction(env, { chatId, mode: payload.action, msgId: null, cbId: null, origin });
    }
    return;
  }

  if (!msg.text) return;
  const text = msg.text.trim();
  const state = (await getState(env, chatId)) || { mode: "home" };

  if (text === "/start" || text === "/help") {
    await setState(env, chatId, { mode: "home" });
    await registerUser(env, chatId);
    await sendMenu(env, chatId, msg.from, origin);
    return;
  }

  if (state.mode === "await_query") {
    if (text.length < 2) {
      await tgSend(env, chatId, "⚠️ اسم کوتاهه، یکم بیشتر بنویس.");
      return;
    }
    await runSearch(env, chatId, text);
    return;
  }

  // Default: any text in home mode re-opens menu
  await setState(env, chatId, { mode: "home" });
  await sendMenu(env, chatId, msg.from, origin);
}

// ---------- Worker entrypoints ----------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/" ) return new Response("OK");
    if (url.pathname === "/menu") {
      return new Response(menuHtml(), { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
    }
    if (url.pathname === "/assistant") {
      return new Response(assistantHtml(), { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
    }
    if (url.pathname === "/ai") {
      return new Response(assistantAiHtml(), { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
    }
    if (url.pathname.startsWith("/api/")) {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
          },
        });
      }
      return handleApi(request, env, url.pathname);
    }
    if (url.pathname === "/setup-webhook") {
      if (!isAdminAuthorized(request, env, url)) return new Response("Unauthorized", { status: 401 });
      const webhookUrl = `${url.origin}/webhook`;
      const webhookBody = { url: webhookUrl };
      // Register the secret with Telegram so it echoes it back as the
      // X-Telegram-Bot-Api-Secret-Token header on every future push — that's
      // what /webhook checks below to make sure a request really came from
      // Telegram and not from someone who merely found this worker's URL.
      if (env[WEBHOOK_SECRET_ENV]) webhookBody.secret_token = env[WEBHOOK_SECRET_ENV];
      const r = await fetch(`${TG(env[BOT_TOKEN])}/setWebhook`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(webhookBody),
      });
      const menuBtnResp = await tgSetMenuButton(env, url.origin);
      const menuBtnResult = await menuBtnResp.json().catch(() => ({ ok: false, error: "menu button request failed" }));
      return new Response(JSON.stringify({
        webhook: await r.json(),
        menu_button: menuBtnResult,
        secret_token_registered: Boolean(env[WEBHOOK_SECRET_ENV]),
      }, null, 2), {
        headers: { "Content-Type": "application/json" },
      });
    }
    if (url.pathname === "/webhook-info") {
      if (!isAdminAuthorized(request, env, url)) return new Response("Unauthorized", { status: 401 });
      const r = await fetch(`${TG(env[BOT_TOKEN])}/getWebhookInfo`);
      return new Response(JSON.stringify(await r.json(), null, 2), {
        headers: { "Content-Type": "application/json" },
      });
    }
    if (url.pathname === "/trigger-daily") {
      if (!isAdminAuthorized(request, env, url)) return new Response("Unauthorized", { status: 401 });
      const n = await pushDailyToAll(env);
      return new Response(JSON.stringify({ pushed: n }), {
        headers: { "Content-Type": "application/json" },
      });
    }
    if (url.pathname === "/webhook" && request.method === "POST") {
      // Reject anything that isn't actually from Telegram BEFORE touching
      // the body — a forged POST here could otherwise impersonate any chat
      // (fake messages, fake button taps, fake Mini App payloads).
      if (env[WEBHOOK_SECRET_ENV]) {
        const supplied = request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
        if (!timingSafeEqual(supplied, env[WEBHOOK_SECRET_ENV])) {
          return new Response("Unauthorized", { status: 401 });
        }
      }
      let update = null;
      try { update = await request.json(); } catch (e) { console.error("webhook: bad JSON body", e); }
      ctx.waitUntil(
        handleUpdate(update, env, url.origin).catch((e) => console.error("handleUpdate failed", e))
      );
      return new Response("OK");
    }
    return new Response("Not found", { status: 404 });
  },

  async scheduled(event, env) {
    const count = await pushDailyToAll(env);
    console.log(`daily push: sent to ${count} users`);
  },
};

// ponytail: STATE_KV + KV dedup skipped - per-chat state only, 30-min TTL is enough,
// and suggestion list is freshly recomputed each morning by the cron (since we
// don't store per-user favorites yet). Add STATE_KV binding when we need cross-chat
// features (favorites, watch history).
// Wait — state DOES need STATE_KV. Without it, search mode is useless.
