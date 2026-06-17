Map a TypeScript/JavaScript repository for downstream SAST analysis. Classifies files by role, identifies HTTP entry points and routes, and writes crawl-output.json.

Called by sast-full-scan when detect-language identifies TypeScript or JavaScript as a significant language.

## Input

`$ARGUMENTS` format: `<repo-path> [--include-tests]`

- `<repo-path>` — absolute or relative path to the repository root
- `--include-tests` — if omitted, test files are excluded

---

## Step 1 — Collect files

Walk `<repo-path>` recursively. Collect `.ts`, `.tsx`, `.js`, `.jsx` files.

Exclude these directories entirely:
`.git/`, `node_modules/`, `dist/`, `build/`, `.next/`, `coverage/`, `.cache/`, `out/`

Exclude test files unless `--include-tests` is passed:
- Files under `__tests__/`
- Files ending in `.test.ts`, `.spec.ts`, `.test.tsx`, `.spec.tsx`, `.test.js`, `.spec.js`

If total file count exceeds 400:
- List top 5 directories by file count
- Ask user to confirm or narrow the path before continuing

---

## Step 2 — Classify each file by role

Scan the first 120 lines for markers. Apply the FIRST matching role:

| Role | Markers |
|---|---|
| `entry_point` | **React/Next.js pages**: file directly in `pages/`, `app/` (Next.js), or exports a default component that is the page root. **React Router**: `<Route path=`, `createBrowserRouter`, `useRoutes` with path definitions. **Express/Node**: `app.get(`, `app.post(`, `router.get(`, `router.post(`, `express.Router()`. **API routes**: file in `pages/api/` or `app/api/` (Next.js). |
| `middleware` | `NextResponse` in Next.js `middleware.ts`, Express `app.use(`, files named `middleware*`, `auth*`, `guard*`, authentication HOCs/wrappers |
| `service` | Filename ends in `.service.ts`, `*Api.ts`, `*Client.ts`, `*Service.ts`; files with `axios.`, `fetch(`, `useQuery`, `useMutation` making API calls; files in `services/`, `api/` (non-route) |
| `dao` | RTK Query `createApi`, direct API fetch wrappers with CRUD operations, GraphQL query files, files in `graphql/`, `queries/` |
| `model` | TypeScript `interface`, `type`, `enum` definitions only; files in `types/`, `models/`, `interfaces/`; no function logic |
| `component` | React component files (`.tsx`) in `components/`; functional components with JSX, no routing logic |
| `config` | `*.config.ts`, `*.config.js`, `next.config.js`, `vite.config.ts`, environment imports (`process.env`, `import.meta.env`), constants files |
| `util` | Everything else |

---

## Step 3 — Extract routes from entry_point files

**Next.js file-based routing:**
- Each file in `pages/` = one route; derive the URL from the file path (`pages/user/[id].tsx` → `/user/:id`)
- Each file in `pages/api/` = one API endpoint
- Each file in `app/` directory with `page.tsx` or `route.ts` = one route (App Router)

**React Router:**
Read the full entry_point file and extract:
```tsx
<Route path="/users/:id" element={<UserPage />} />
// or
{ path: "/users/:id", element: <UserPage /> }
```

**Express/Node:**
Read the full entry_point file and extract:
```js
router.get("/users/:id", handler)
app.post("/auth/login", handler)
```

---

## Step 4 — Detect framework and dependencies

Read `package.json` at the repo root (or `frontend/package.json`, `client/package.json` if no root package.json):

**Framework detection from `dependencies`:**
- `next` → `nextjs`
- `react` + `react-dom` (no `next`) → `react`
- `express` → `express`
- `fastify` → `fastify`
- `vue` → `vue`
- `@angular/core` → `angular`
- `svelte` → `svelte`

**Node version:** from `.nvmrc`, `.node-version`, or `engines.node` in `package.json`.

**Security-sensitive packages to flag:**
- Present and dangerous: `eval` in code (not a package), `dangerouslySetInnerHTML` usage, `mermaid` with `securityLevel`
- Missing protection: absence of `dompurify` when `innerHTML` is used, absence of `helmet` in Express apps
- Packages: `jsonwebtoken`, `node-forge`, `crypto-js`, `vm2`, `serialize-javascript`

---

## Step 5 — Write crawl-output.json

Write to `crawl-output.json` in the current working directory. Overwrite if exists.

```json
{
  "repo_path": "<absolute path>",
  "scanned_at": "<ISO 8601 timestamp>",
  "language": "typescript",
  "languages_detected": ["typescript"],
  "runtime_version": "18",
  "framework": "react",
  "total_files": 0,
  "entry_points": [
    {
      "path": "frontend/src/App.tsx",
      "role": "entry_point",
      "routes": [
        { "method": "GET", "path": "/chat", "handler": "ChatPage" },
        { "method": "GET", "path": "/projects/:id", "handler": "ProjectPage" }
      ]
    }
  ],
  "files": [
    {
      "path": "frontend/src/components/chat/ChatComponent.tsx",
      "role": "component",
      "lines": 120,
      "language": "typescript"
    }
  ],
  "dependencies": [
    { "name": "react", "version": "18.3.1", "security_sensitive": false },
    { "name": "mermaid", "version": "10.9.1", "security_sensitive": true }
  ],
  "skipped_files": [],
  "warnings": []
}
```

---

## Constraints

- Skip files exceeding 5000 lines — add to `skipped_files` with reason `exceeds line limit`
- Skip binary files — add to `skipped_files` with reason `binary`
- Role detection reads only the first 120 lines; route extraction reads the full file
- `.js` and `.jsx` files: classify with the same rules — TypeScript markers also appear in JS files
- If the repo is a monorepo with separate `frontend/` and `backend/` directories, note it in `warnings[]` and crawl both sub-trees

---

## Completion

```
crawl-typescript complete.
  Repo        : <repo-path>
  Framework   : <framework> (Node <version>)
  Files       : <N> .ts/.tsx + <N> .js/.jsx files mapped
  Entry points: <N> routes across <N> files
  Components  : <N> files
  Services    : <N> files
  Flagged deps: <list>
  Output      : crawl-output.json
```
