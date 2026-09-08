# Page Maps — Every Page With Its Ads

Wireframes of the panel and entry pages that carry ads, plus a table of the
content pages. Ad annotations show:

- **company**: Effective CPM (all units) · Adstera (disabled)
- **type**: head loader · banner (invoke) · native · popunder · social bar
- **device**: D = desktop · M = mobile · B = both

Carrying slots is not the same as being switched on. Of the pages wireframed
below only `index` is **default on**; `user_login`, `user_register`,
`user_dashboard`, `user_bot_editor`, `user_bot_replies` and `user_formatting`
are **default off** — the six account/credential endpoints advertising used to
refuse outright, now a default an admin can overrule rather than a literal in
`frontend.py`. `blocked` has no switch because it has no units. The remaining
default-on pages (`about`, `hosting`, `contact`, `help`, `blog`, `blog_post`,
`terms`, `privacy`) are tabulated at the end instead of wireframed.

All markup comes from `ads_config.py`; slots render via `ad_unit('<zone>')`,
which asks `ad_zone()` first. A unit reaches the browser only if every one of
these agrees:

- **master switch** `ads_enabled` — off means no units and no head loaders
- **per-user** `users.ads_disabled` — blanks every page and zone for one account
- **cookie consent** — an explicit decline always blocks; with
  `ad_consent_required` on, an unanswered banner blocks too
- **page switch** `ad_page_<endpoint>` — the endpoint being rendered, defaulting
  to that row's `default_on` in `database.AD_PAGES`
- **zone switch** `ad_zone_<zone>` — the global toggle, then this user's
  per-zone override
- **network switch** `ad_network_<id>` — the unit's own provider, checked by
  `ad_unit()`; with every network off no zone resolves on at all

The page switch and the zone switch are independent axes, not a chain: both must
say yes and neither overrules the other. A page being on does not make a zone
render, and a zone being on does not put ads back on a page whose switch is off
— which is what lets the console say "no ads on the sign-in page" without
touching the zones that page shares with the home page. The resolution order
lives in `database.get_resolved_ad_pages()` and `get_resolved_ad_zones()`; the
page answer reaches a template through `frontend._ads_permitted()`, which
`ad_zone()`, `ad_head()` and the guard-mode processor all consult.

Legend for unit sizes:

| Zone | Company | Type | Size | Device |
|---|---|---|---|---|
| leaderboard | Effective CPM | banner invoke | 728×90 | D |
| mobile | Effective CPM | banner invoke | 320×50 | M |
| native | Effective CPM | native invoke | fluid | B |
| banner_468x60 | Effective CPM | banner invoke | 468×60 | D |
| banner_300x250 | Effective CPM | banner invoke | 300×250 | B |
| banner_160x600 | Effective CPM | banner invoke | 160×600 | D |
| banner_160x300 | Effective CPM | banner invoke | 160×300 | D |
| popunder_entry | Effective CPM | popunder (pageleave) | — | B |
| social_bar | Effective CPM | social bar (floating) | — | B |
| (head loader) | Legacy ad loader | legacy tag loader | — | B |
| (head loader) | Adstera | blank loader — **wired in, not configured** | — | B |

---

## 1. index.html — landing page

Endpoint `index`, **default on** — the only wireframe here that advertises out of
the box (`ad_page_index` turns it off).

```
┌────────────────────────────────────────────────────────────┐
│ NAV: logo ─ how · features · faq · reviews ─ login signup   │
├────────────────────────────────────────────────────────────┤
│ HERO: "Free" + Discord CTA                [hero visual]    │
├────────────────────────────────────────────────────────────┤
│ HOW IT WORKS · FEATURES · FAQ · REVIEWS  (long scroll)     │
├────────────────────────────────────────────────────────────┤
│ ◢ head: legacy ad network loader ───────────────────── L4 │
│ ┌──────────────────────────────────────────────────────┐   │
│ │ AD ▸ Effective CPM · banner 728×90 · DESKTOP         │   │
│ │     leaderboard ───────────────────────────── L246   │   │
│ └──────────────────────────────────────────────────────┘   │
├────────────────────────────────────────────────────────────┤
│ FOOTER: product · community · legal │ "Endevil"            │
├────────────────────────────────────────────────────────────┤
│ AD ▸ Effective CPM · banner 320×50 · MOBILE ── L278       │
│ AD ▸ Effective CPM · popunder pageleave · BOTH ── L279    │
│ AD ▸ Effective CPM · social bar floating · BOTH ── L280   │
│ (ads.js loader ────────────── L281)                        │
└────────────────────────────────────────────────────────────┘
```

## 2. user_login.html — login page

Endpoint `user_login`, **default off** — the units below are in the markup but
render only once an admin enables `ad_page_user_login`.

```
┌────────────────────────────────────────────────────────────┐
│ NAV: logo ───────────────────────── login · register        │
│ ◢ head: legacy ad loader ─────────────────────────────── L4│
├────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────┐ ┌──────────────────────┐   │
│  │ LOGIN card                 │ │ aside: promo copy    │   │
│  │ username / password        │ │ (no ads)             │   │
│  │ [Log in]                   │ └──────────────────────┘   │
│  └────────────────────────────┘                           │
│ ┌──────────────────────────────────────────────────────┐   │
│ │ AD ▸ Effective CPM · banner 728×90 · DESKTOP         │   │
│ │     leaderboard ───────────────────────────── L79    │   │
│ └──────────────────────────────────────────────────────┘   │
├────────────────────────────────────────────────────────────┤
│ FOOTER                                                      │
│ AD ▸ Effective CPM · banner 320×50 · MOBILE ── L81        │
│ AD ▸ Effective CPM · popunder pageleave · BOTH ── L82     │
│ AD ▸ Effective CPM · social bar · BOTH ────────── L83     │
│ (ads.js ─────────────────────── L84)                       │
└────────────────────────────────────────────────────────────┘
```

## 3. user_register.html — signup page

Endpoint `user_register`, **default off** — the units below are in the markup but
render only once an admin enables `ad_page_user_register`.

```
┌────────────────────────────────────────────────────────────┐
│ NAV                                                         │
│ ◢ head: legacy ad loader ─────────────────────────────── L4│
├────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────┐ ┌──────────────────────┐   │
│  │ REGISTER card              │ │ aside (no ads)       │   │
│  │ username/email/password    │ └──────────────────────┘   │
│  │ OTP step · [Create]        │                           │
│  └────────────────────────────┘                           │
│ ┌──────────────────────────────────────────────────────┐   │
│ │ AD ▸ Effective CPM · banner 728×90 · DESKTOP         │   │
│ │     leaderboard ───────────────────────────── L131   │   │
│ └──────────────────────────────────────────────────────┘   │
│ FOOTER                                                      │
│ AD ▸ Effective CPM · banner 320×50 · MOBILE ── L133       │
│ AD ▸ Effective CPM · popunder pageleave · BOTH ── L134    │
│ AD ▸ Effective CPM · social bar · BOTH ────────── L135    │
│ (ads.js ─────────────────────── L136)                       │
└────────────────────────────────────────────────────────────┘
```

## 4. user2.html — dashboard / embed builder

Endpoint `user_bot_editor` (`/user/bot/<id>`), **default off** — the units below
are in the markup but render only once an admin enables
`ad_page_user_bot_editor`.

```
┌────────────────────────────────────────────────────────────┐
│ NAV: logo · BOTS · SLOTS · DISCORD · SETTINGS · logout      │
│ ◢ head: legacy ad loader ─────────────────────────────── L4│
├────────────────────────────────────────────────────────────┤
│ ┌──────────────────────────────┐ ┌──────────────────────┐  │
│ │ BOT CONFIG                    │ │ EMBED PREVIEW        │  │
│ │ ip · port · edition           │ │ [discord-chat mock]  │  │
│ │ token · guild · channel       │ │ ┌──────────────────┐ │  │
│ │ widgets + add-widget          │ │ │ AD ▸ Effective   │ │  │
│ │ [Save] [Preview] [Refresh]    │ │ │  CPM · banner    │ │  │
│ └──────────────────────────────┘ │ │  160×600 ·        │ │  │
│                                  │ │  DESKTOP (sidebar)│ │  │
│                                  │ │  banner_160x600   │ │  │
│                                  │ │  ────────── L204  │ │  │
│                                  │ └──────────────────┘ │  │
│                                  └──────────────────────┘  │
├────────────────────────────────────────────────────────────┤
│ modal: settings · toast                                     │
│ AD ▸ Effective CPM · banner 320×50 · MOBILE ── L1463       │
│ AD ▸ Effective CPM · social bar · BOTH ────────── L1464    │
│ (ads.js ─────────────────────── L1466)                       │
└────────────────────────────────────────────────────────────┘
```

## 5. replies.html — IP reply builder

Endpoint `user_bot_replies` (`/user/bot/<id>/replies`), **default off** — the
units below are in the markup but render only once an admin enables
`ad_page_user_bot_replies`.

```
┌────────────────────────────────────────────────────────────┐
│ NAV: logo · <user> · EMBED BUILDER · HOME · logout         │
│ ◢ head: legacy ad loader ─────────────────────────────── L4│
├────────────────────────────────────────────────────────────┤
│ ┌──────────────────────────────────────────────────────┐   │
│ │ AD ▸ Effective CPM · banner 728×90 · DESKTOP         │   │
│ │     leaderboard ───────────────────────────── L29    │   │
│ └──────────────────────────────────────────────────────┘   │
├────────────────────────────────────────────────────────────┤
│ CARD: "IP Reply — <bot>" · enable · saved-state pill       │
│ ┌──────────────────────────────┐ ┌──────────────────┐      │
│ │ TRIGGER word                 │ │ PREVIEW          │      │
│ │ REPLY TYPE plain / embed     │ │ [discord-chat    │      │
│ │  message text                │ │  mock]           │      │
│ │  title / desc / footer       │ │ (no ads)         │      │
│ │  accent colour               │ └──────────────────┘      │
│ │ PLACEHOLDERS {ip} {port} …   │                           │
│ │ [Save IP Reply]              │                           │
│ └──────────────────────────────┘                           │
├────────────────────────────────────────────────────────────┤
│ toast                                                      │
│ AD ▸ Effective CPM · banner 320×50 · MOBILE ── L117        │
│ AD ▸ Effective CPM · social bar · BOTH ────────── L118     │
│ (ads.js ─────────────────────── L120)                      │
└────────────────────────────────────────────────────────────┘
```

## 6. slots.html — manage bot slots

Endpoint `user_dashboard` (`/user`), **default off** — the units below are in the
markup but render only once an admin enables `ad_page_user_dashboard`.

```
┌────────────────────────────────────────────────────────────┐
│ NAV                                                         │
│ ◢ head: legacy ad loader ─────────────────────────────── L4│
│ ┌──────────────────────────────────────────────────────┐   │
│ │ AD ▸ Effective CPM · banner 728×90 · DESKTOP         │   │
│ │     leaderboard ───────────────────────────── L79    │   │
│ └──────────────────────────────────────────────────────┘   │
├────────────────────────────────────────────────────────────┤
│  SLOT CARDS (bot name · status · start/stop · edit)        │
├────────────────────────────────────────────────────────────┤
│ ┌──────────────────────────────────────────────────────┐   │
│ │ AD ▸ Effective CPM · native (fluid) · BOTH           │   │
│ │     native ────────────────────────────────── L81    │   │
│ └──────────────────────────────────────────────────────┘   │
│  upgrade-to-more-slots CTA                                  │
├────────────────────────────────────────────────────────────┤
│ AD ▸ Effective CPM · banner 320×50 · MOBILE ── L186       │
│ AD ▸ Effective CPM · social bar · BOTH ────────── L187    │
│ (ads.js ─────────────────────── L189)                       │
└────────────────────────────────────────────────────────────┘
```

## 7. discord_formatting.html — docs page

Endpoint `user_formatting` (`/user/formatting`), **default off** — the units below
are in the markup but render only once an admin enables
`ad_page_user_formatting`.

```
┌────────────────────────────────────────────────────────────┐
│ NAV                                                         │
│ ◢ head: legacy ad loader ─────────────────────────────── L4│
│ ┌──────────────────────────────────────────────────────┐   │
│ │ AD ▸ Effective CPM · native (fluid) · BOTH           │   │
│ │     native ────────────────────────────────── L80    │   │
│ └──────────────────────────────────────────────────────┘   │
│ ┌──────────────────────────────────────────────────────┐   │
│ │ AD ▸ Effective CPM · banner 160×300 · DESKTOP        │   │
│ │     banner_160x300 ──────────────────────── L82      │   │
│ └──────────────────────────────────────────────────────┘   │
├────────────────────────────────────────────────────────────┤
│  DOCS: formatting guide (markdown, fields, embeds)         │
├────────────────────────────────────────────────────────────┤
│ AD ▸ Effective CPM · banner 320×50 · MOBILE ── L85        │
│ AD ▸ Effective CPM · social bar · BOTH ────────── L86     │
│ (ads.js ─────────────────────── L88)                       │
└────────────────────────────────────────────────────────────┘
```

## 8. blocked.html — ad-blocker page (no ad slots)

No `AD_PAGES` row and no switch: it calls `ad_scripts()` only, so there is
nothing for a page switch to govern.

This page is a poll, not a dead end: `g7.js` re-runs the detection 5 s
after the first round and then backs off by doubling to a 30 s ceiling, standing
down entirely while the tab is hidden and re-checking immediately on the way
back. Each round drops the cached network verdict and re-probes the ad unit whose
`<script>` actually failed — recorded in `sessionStorage` as
`fp_guard_failed_unit`, so it is set only when a unit is what sent the visitor
here — then forwards them back to where they came from once both read clean.
Landing here is not guaranteed either: the guard counts its own round trips in
`fp_guard_bounces` and after 2 inside 60 s stands down for the rest of that
window, revealing the guarded page with a dismissible warning banner instead.

```
┌────────────────────────────────────────────────────────────┐
│ ⚠ AD BLOCKER DETECTED — "Please whitelist us"              │
│ No units render here. ads.js is loaded as the detection    │
│ trap only (L57) — its load success/failure triggers the    │
│ block notice.                                               │
└────────────────────────────────────────────────────────────┘
```

---

## Default-on content pages

These carry ad code too, but their layout is the same nav → leaderboard → body →
footer → mobile/social bar shell the wireframes above already show, so they are
tabulated rather than drawn. All are `default_on: True` in `database.AD_PAGES`,
i.e. they advertise until an admin turns their row off.

| Template | Endpoint | Head | Slots, top to bottom |
|---|---|---|---|
| about.html | `about` | L4 | leaderboard L44 · mobile L99 · social_bar L100 |
| hosting.html | `hosting` | L4 | leaderboard L44 · mobile L118 · social_bar L119 |
| contact.html | `contact` | L4 | leaderboard L44 · mobile L105 · social_bar L106 |
| help.html | `help` | L4 | leaderboard L46 · banner_468x60 L61 + banner_300x250 L62 (`.ad-pair`) · mobile L453 · social_bar L454 |
| blog.html | `blog` | L4 | leaderboard L45 · banner_468x60 L54 + banner_300x250 L55 (`.ad-pair`) · mobile L90 · social_bar L91 |
| blog_post.html | `blog_post` | L4 | leaderboard L96 · mobile L144 · social_bar L145 |
| terms.html | `terms` | L4 | none — head loader only |
| privacy.html | `privacy` | — | none; emits no ad code at all, so its switch is inert |

`terms` and `privacy` are in `AD_PAGES` because a head loader is ad code on its
own — a legacy head loader can still serve without a slot beneath it — and an endpoint
with no row is waved through by `_ads_permitted()` with no switch reaching it.
`privacy` rides along for symmetry so the pair cannot silently diverge.

---

## Company / device summary

| Company | What it serves | Where |
|---|---|---|
| **Legacy ad loader** | legacy head loader | `<head>` of templates that call `ad_head()` |
| **Effective CPM** | Every display unit (highperformanceformat.com + effectivecpmnetwork.com invoke.js) | the 13 templates carrying `ad_unit()` calls — every ad page except terms/privacy |
| **Effective CPM** | Social bar (pl29657149) | bottom of all 13 unit-carrying pages |
| **Effective CPM** | Popunder (pl29657147) | entry pages only: index, user_login, user_register |
| **Adstera** | — | `ads_config.py:88-93` — entry exists with a blank loader, so `ad_head_html()` skips it; paste the dashboard loader/zone to enable |

`database.AD_PAGES` has 15 rows: 9 default on (index, about, hosting, contact,
help, blog, blog_post, terms, privacy) and 6 default off (user_login,
user_register, user_dashboard, user_bot_editor, user_bot_replies,
user_formatting). blocked.html, banned.html and rate_limited.html call only
`ad_scripts()` — the fingerprint/guard pair, not advertising — so they have no
row and no switch.

Device split: desktop-only units are the 728×90 leaderboard and the skyscraper
banners (160×600, 160×300, 468×60); the 320×50 `mobile` unit is mobile-only;
native, popunders and social bar render on both. Responsive layouts show the
mobile unit instead of the leaderboard via the `ad-mobile` CSS class.
