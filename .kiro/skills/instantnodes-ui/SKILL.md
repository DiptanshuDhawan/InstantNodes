---
name: instantnodes-ui
description: Design system, copy rules, legal guardrails and verification workflow for the InstantNodes (NetSimX) frontend. Use when designing, restyling or reviewing any InstantNodes page or component (home page, lab library, lab workspace, top bar, logo, topology diagrams, icons), or when adding fonts, visual assets or user-facing text to frontend/.
metadata:
  project: NetSimX / InstantNodes
  version: "1.1"
---

# InstantNodes UI

Use together with the `frontend-design` skill: that skill gives the general method (plan, review
against the brief, build, critique); this one gives the decisions already made for this product.

## Subject and audience
- Product: InstantNodes, a browser-based Cisco IOS lab simulator. Learners configure simulated
  routers, switches and PCs from a console and grade their work task by task.
- Audience: CCNA 200-301 candidates (students, career changers, junior network admins) who know
  tools such as commercial network simulators, Packet Tracer and GNS3.
- Every screen should feel like simulator software, not a marketing site: real lab data, real
  device names, real status. No invented numbers or testimonials.

## Pages and flow
- `/` home page (`app/page.js`, server component; parts in `components/landing/`): what the
  simulator is, how a lab runs, what is simulated, the labs, accounts, footer. Its job is to send
  people to the lab library. Signed-in users also get it (with "Resume your lab"); no redirect.
- `/labs` lab library (`components/library/LabLibrary.js`): the simulator's home screen with the
  lab list, the briefing and the guide. `/labs?lab=<slug>` opens with that lab selected (the
  home page's lab rows link there).
- `/labs/<slug>` lab workspace (`app/labs/[slug]/page.js`, header `components/lab/TopNav.js`).
- `/login`, `/signup`, `/account`: see Accounts. After signing in without `?next=` people land
  on `/labs`.

## Brand and top bar
- Logo (`components/site/Logo.js`, same drawing in `app/icon.svg`): an N drawn as a network
  path on a `#17365D` tile with a `rgba(108,180,255,.35)` edge; path `#6CB4FF`, nodes `#E6F1FF`,
  the last node green `#34D27B` like a link LED. Wordmark "InstantNodes" in IBM Plex Sans 600 at
  `font-stretch: 87%`. Never bring back the spaced INSTANT / NODES lettering, and put no
  descriptor ("Cisco IOS lab simulator") next to the logo; the user rejected both.
- Top bar (`components/site/SiteHeader.js`, `site.module.css`): full-bleed 60px bar (56px under
  860px) with a bottom line: logo, main nav (Labs, How it works `/#how`, What's simulated
  `/#simulated`; the last two hide under 860px), then page items (`children`, e.g. the server
  status pill on `/labs`) and the account area. `contained` lines it up with the home page's
  1248px column, `sticky` keeps it on screen there. The current section gets `aria-current` and
  a blue underline; the account chip gets `aria-current` on `/account`.
- The lab workspace keeps its own rounded header card (`.nx-header`) with the same `Logo` and a
  "Labs" link back to the library.

## Direction: the simulator's own screens
- Library, account and workspace pages share the lab workspace frame: 12px outer padding, 16px
  gaps, panels on the dotted base (`globals.css`: `--bg-base #1A1C1E`, `--bg-card #222428`,
  `--primary #2F80ED`).
- Home page: the hero shows one scripted moment of Lab 02 (`SimulatorPreview.js`, CSS only,
  played once): R1 is configured, OSPF reaches FULL, Grade is pressed, the lab's real four tasks
  pass and the score shows 100%. It is the page's one bold element. Below it: three stages of a
  lab joined by a dashed cable (their examples are real simulator output: `network ?` help and a
  real grade report), a spec table, the lab rows from the API, the account band. No stats strip,
  no gradient hero, no eyebrow labels.
- Lab library: lab list (left), lab briefing with the real topology (centre), "How labs work"
  and "What's simulated" (right). The server status lives in the top bar pill.
- Equipment vernacular, used for information only:
  - LEDs show state: green `#34D27B` completed or online, amber `#F4B740` in progress or
    connecting, red `#F0605D` offline or error, off `#3A3E45` not started.
  - The progress meter is a row of RJ45 port glyphs, one per lab, with link/activity LEDs.
  - Topology diagrams sit in a dotted "bench" well, as on the lab page. Hovering a device in a
    list highlights it on the diagram (`activeNode`).
- One bold element per screen (home page: the preview; library: the bench). Everything else
  stays quiet.

## Tokens
- Type: IBM Plex Sans (variable, `--font-sans`, wdth 75-100) for all UI text; titles, lab numbers
  and panel titles use `font-stretch: 80-85%` and weight 600 (chassis-label feel). IBM Plex Mono
  (`--font-mono`, 400 and 500) only for real CLI artifacts: commands, prompts, interface names.
  Fonts load through `next/font/google` in `src/app/fonts.js`; both variables are set on `<html>`
  in `layout.js` (the logo appears on every page), and each page module sets `font-family`. The
  lab workspace body text stays Inter (`globals.css`). Never `@import` Google Fonts in new code.
- Text colours: `#F3F5F8` primary, `#A9B2BF` secondary, `#8A94A2` tertiary (5:1 on `#222428`;
  darker greys fail WCAG AA for small text). Blue text and focus: `#6CB4FF`.
- Primary button: gradient `#2B6FE3` to `#2360DA` with white text (4.7:1); the lab page's
  `#2F80ED` is too light for white 14px text.
- Lines: `rgba(255,255,255,0.07)`, strong `rgba(255,255,255,0.13)`.
- Radii by role: workspace header card 16px, panels 12px, bench well 10px, buttons 12px (as the
  lab page's Grade button; 10px for the small top bar buttons), chips and badges 6px, port glyphs
  3px. The site top bar is full-bleed and square.
- Focus ring: 2px `#6CB4FF`, offset 2px, on every interactive element.

## Layout notes
- Home page: content column max 1248px with 24px side padding (16px under 860px). Hero is two
  columns down to 1100px, then the preview goes under the text. Stages are a 3-column subgrid
  (number, title, text, example line up); one column under 860px.
- Sections that the top bar links to need `scroll-margin-top` for the sticky bar, and must sit
  above content that loads from the API (or reserve its height), or a jump lands short when the
  list arrives. The lab rows' skeleton has the loaded row height for the same reason.
- Lab library, desktop (1280px and up): top bar, then library (300px), briefing and guide
  (288px) columns that scroll on their own, as in the lab workspace. 860-1279px: the guide moves
  under the briefing and that column scrolls as one (block flow; auto grid rows in a fixed-height
  container shrink the panels). Below 860px: one column and the page scrolls; selecting a lab
  scrolls to its briefing.
- The lab list is a vertical tablist (arrow keys, Home, End; one tab stop) controlling the
  briefing tabpanel. Lab details come from `GET /api/labs/{slug}` on first selection and are
  cached; never show task hints outside the lab workspace.
- `html, body` do not scroll (the lab workspace needs that); every other page scrolls inside its
  own `.page` box (`height: 100dvh; overflow-y: auto`).

## Copy
- Sentence case everywhere. Plain verbs: "Open lab", "Resume lab", "Start Lab 01", "Try again".
- No ALL-CAPS eyebrow labels, no meta strings joined with middle dots, no arrows appended to
  button text, no gradient-coloured words in headlines.
- Number things only when they are a sequence (tasks, steps) or a real identifier (lab numbers).
- Examples of the product (task names, console lines, grade findings) are copied from the real
  labs and simulator output, not made up.
- Errors say what happened and what to do ("The lab server did not respond. Check that it is
  running, then try again."). Empty states invite an action.

## Legal guardrails (do not skip)
- Never copy a competitor's names, logos, colours, layouts, text, screenshots or icons. In
  particular Boson (purple and green brand, "NetSim" is a Boson trademark, "Network Designer" and
  "Lab Navigator" are their feature names) and Cisco Packet Tracer. Describe our features in our
  own words.
- Do not use "NetSim" in any user-facing text or brand. The public brand is InstantNodes.
- Cisco, Cisco IOS and CCNA are Cisco trademarks: use them only descriptively, and keep the notice
  "Cisco, Cisco IOS and CCNA are trademarks of Cisco Systems, Inc. InstantNodes is not affiliated
  with Cisco." on public pages (the home page footer and the library's guide panel have it).
- Device icons are our own SVGs (`src/components/icons/`); do not import vendor icon libraries.

## Accounts (sign-in, progress)
- Pages: `/login`, `/signup` (server pages that pass `?next=` to `LoginForm`/`SignupForm`) and
  `/account` (`AccountView`). The top bar's `AccountArea` shows Sign in / Create account (back
  to the current page), or the avatar chip linking to `/account`.
- `useAuth()` (`components/auth/AuthProvider.js`) gives `status` (loading, signed-in,
  signed-out, offline), `user`, `signIn`, `signUp`, `signOut`. Never keep tokens in JavaScript:
  the API sets an HttpOnly cookie and `lib/api.js` sends `credentials: 'include'`.
- Pages that need an account redirect with `router.replace(loginHref(currentPath))`; links use
  `loginHref`/`signupHref` from `lib/authLinks.js` (only same-site `next` paths are followed).
- Progress, best scores and the running lab come from `GET /api/progress`, not localStorage.
  For visitors the call to action reads "Sign in to open Lab NN".
- Show API errors with `apiErrorMessage(error, fallback)`: it returns the API's own sentence
  and a clear message when the server did not answer.
- Words: Sign in, Sign out, Sign out on all devices, Create account, Change password.

## Engineering rules
- Read the relevant guide in `frontend/node_modules/next/dist/docs/` before writing code
  (Next.js 16.4 differs from older versions; see `frontend/AGENTS.md`).
- Styles go in a CSS Module next to the component that owns them (`components/landing/`,
  `components/library/`, `components/account/`, `components/site/`); shared tokens stay in
  `globals.css`. Do not add dependencies without asking the user.
- `react-hooks/set-state-in-effect` is enforced: set state in promise callbacks or event handlers,
  not synchronously in an effect body.
- Respect `prefers-reduced-motion` (the home page preview then shows its final state); motion
  only answers a user action (selection change), shows live state (connecting LED) or is the
  home page's one scripted preview.

## Verify before reporting
1. `npx --no-install eslint src` (cwd `frontend`) is clean.
2. Stop any dev server, then `node node_modules\next\dist\bin\next build` succeeds.
3. Screenshots with `NetSimX-work\ui\cdpshot.mjs` (the local work folder next to the repo, not
   in git; run from that folder) at
   1440x900, 1280x800, 1024x768 and 390x844 `--mobile` (360 for the top bar);
   `--full --split 1200` for long pages; `--wait 9000` on `/` so the preview has finished.
   Pages: `/` signed out and in, `/labs` and `/labs?lab=roas-2`, `/account`, `/login`, and the
   lab page (`/labs/roas-1`) when shared styles, the logo or fonts change. States: first visit,
   returning user (`--storage returning.json`), API down on `/labs`
   (`--block "*127.0.0.1:8010*"`, then `--click "Try again"`). `--eval <js>` prints a page
   value, `--hover <selector>` moves the real pointer (selectors without spaces or quotes, e.g.
   `li[title^=SW1]`), `--clip x,y,w,h` zooms in at 3x (hover is lost in clip shots).
   `--evalfile file.js` runs a script file (no shell quoting problems; `probe-hashnav.js` checks
   the top bar's section links, `probe-flow.js` clicks home, library, lab); `--prep file.js`
   runs a script on a first load, then reloads (e.g. `prep-login-alex.js` signs in the seeded
   account from `NetSimX-work\auth\seed_ui_user.py`). The test API needs
   `CORS_ORIGINS=http://127.0.0.1:3011` for the dev server on 3011.
4. Read each PNG in its own tool call after the shot finishes, and look at it critically: remove
   one accessory before calling it done.
