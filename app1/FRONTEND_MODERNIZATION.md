Read `app1/CLAUDE.md` and `app1/FRONTEND_MODERNIZATION.md`.

I want you to fully modernize the frontend of `app1/` according to those instructions.

Before modifying anything:

1. Inspect the existing frontend architecture.
2. Inspect the existing advertisement implementation, especially `ads_config.py`, `ads.txt`, `check_ad_gates.py`, and all existing ad-rendering/admin-control code.
3. Inspect the existing routes, templates/components, CSS, JavaScript, authentication and responsive layout.
4. Use parallel agents for independent frontend, advertising, UX and security investigation where useful.
5. Do NOT rewrite working backend functionality just to redesign the frontend.
6. Do NOT replace the existing admin-controlled advertising system.

Then implement the redesign.

I want the entire `app1/` frontend to feel like a modern production SaaS/web platform, not just a redesigned homepage.

Add reusable advertisement placement components/slots where there is suitable layout space, including desktop side/rail areas, inline content areas, banners and other appropriate locations.

However, do NOT simply fill every blank area with ads.

Ads must remain:

* controlled by the existing admin system
* optional/disableable
* clearly distinguishable from site content
* separated from interactive controls
* responsive
* compatible with Google's current AdSense placement policies

Do not claim that the implementation guarantees AdSense approval.

Preserve all existing functionality, routes, authentication, APIs, permissions, admin controls and security boundaries.

After implementation, use Playwright to inspect the actual application at desktop, tablet and mobile sizes. Take screenshots where useful, check console errors, check layout problems, verify advertisements do not overlap controls, and fix any issues you find.

Do not stop after the first page. Modernize the complete relevant frontend.

Do not create unnecessary documentation files or perform unrelated refactoring.

When finished, give me a short summary of:

* what frontend areas were redesigned
* what reusable components were created
* where ad slots were added
* how the existing admin ad controls were preserved
* browser/tests performed
* remaining issues, if any
