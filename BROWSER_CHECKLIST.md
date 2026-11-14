# BROWSER_CHECKLIST.md  (manual validation in Chrome; STATUS: NOT YET RUN)

Nothing in this project has been verified in a real browser. Run this before showing the page to anyone, then repeat the starred items in Firefox.

Start: `python3 -m app.server --port 8000`, open `http://127.0.0.1:8000/`, open DevTools (F12) on **Console** and **Network**.

1. **First load.** Console shows no errors and no "Content Security Policy" violations. Network shows only requests to 127.0.0.1:8000 (page, style.css, app.js, demo-story). *
2. **Story panel.** "Loading the demo…" disappears. Left: "20 questions → exactly $120,000". Right: 9 rows (Start + 8 steps) with candidates 1,000,000 → 500,001 → 250,001 → 125,001 → 62,500 → 31,250 → 15,625, then two REFUSED rows; bars shrink; a dashed red line sits at the 1% position and no bar after step 6 goes left of it. The summary reads "15,625 candidates remain (floor 10,000)". *
3. **Layout.** No horizontal page scroll at 1280 px and at 375 px (DevTools device toolbar); tables scroll inside their own box; text is not clipped.
4. **Dark mode.** DevTools ⋮ → More tools → Rendering → "Emulate prefers-color-scheme: dark": text, banner, bars, dashed floor line and buttons stay legible.
5. **Create session by keyboard.** Click the income field, type 120000, press **Enter**: session is created, "No session yet." disappears, focus moves to the threshold field, Ask becomes enabled. Type -5 + Enter: a red message appears and nothing else changes. *
6. **Ask by keyboard.** In the threshold field type 9998, press Enter: verifier panel says "REFUSED: no answer was given"; its table gains one row; the dashed owner/auditor panel shows "REFUSED (reason: FLOOR)". Then 9999 → answered. Then 500000 → "NO: income is at or below $500,000", candidates drop to 500,001 in the owner panel. *
7. **Separation.** Read the whole verifier panel: it must never show a feasible range, candidate count, floor, reason, session secret or token. The same information must appear only in the dashed owner/auditor panel. *
8. **Double click.** Double-click Ask quickly: exactly one new row, button shows disabled while the request runs.
9. **Bad input.** Threshold `abc` or `1.5` → "Threshold must be a whole number." and no new row. Quick buttons fill the threshold field.
10. **Attack demo.** "Run attacker": baseline says exact recovery in 20 questions; gated line says floor held and secret recovered: no; your own session's counters did not change.
11. **Server stopped.** Stop the server (Ctrl+C), click Ask: message "Cannot reach the local server. Is it still running?" and the page stays usable. Restart the server, click Ask again: "Session no longer exists…", buttons disabled, owner panel reset; create a new session and continue. *
12. **Keyboard and focus.** Tab through the page: order is story button → income → options → Create → verifier → threshold → Ask → quick buttons; a visible focus outline appears on each; no keyboard trap. *
13. **Zoom 200%.** The page remains usable.
14. **View source.** No inline `<script>` or `style=` attributes; the only script is `/app.js`.
15. **Labels.** The banner at the top says it is a local simulation, runs only on this computer, has no blockchain, does not encrypt, and uses a mock credential. It does not change after creating a session.

Record results (pass/fail, browser and version, date) here. Anything that fails is a bug to report, not a reason to change the privacy engine.
