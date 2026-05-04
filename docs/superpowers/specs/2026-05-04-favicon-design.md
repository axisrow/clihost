# Favicon Design

## Summary
Add an inline SVG favicon to all HTML pages (login, dashboard, terminal) for browser tab identification.

## Approach
- **Inline SVG data URI** in the `<link rel="icon">` tag — no external files, no server changes.
- Icon: `>_` terminal prompt characters on a dark (#1a1a2e) background in a monospace style.
- Added to all 3 HTML templates: `login.html`, `index.html`, `terminal.html`.

## Scope
- Only HTML `<head>` changes in existing templates.
- No new files, no env vars, no server-side changes.

## Testing
- Verify favicon appears in browser tab on all 3 pages (login, dashboard, terminal).
