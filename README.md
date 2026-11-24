# Keystone MDM

**Free, simple Windows device management for small offices.**

Keystone is an open-source alternative to Intune for offices with 1–50 PCs and no IT department. It uses the management client that is **already built into Windows 10 and 11**, so there is no agent to install. Enroll a PC in a minute, see whether it's healthy, and fix it with one click.

> **Status: early prototype (v0.1).** Enrollment and inventory are working in tests, but they have not yet been tried on real PCs. Don't use it on production machines yet.

## What it does today

- **Enroll PCs** through Windows' own *Access work or school* screen, or a one-click enrollment link
- **See every PC:** name, make and model, Windows version, serial number, memory and storage
- **Health at a glance:** green or red for drive encryption (BitLocker), antivirus and firewall
- **One-click actions:** require drive encryption, keep antivirus on, turn on automatic updates, restart the PC
- **No dependencies:** a single Go binary with only the standard library. Data is stored in one file.

## Quick start (Docker)

1. You need a hostname with a **publicly trusted HTTPS certificate** that Windows PCs can reach, for example `enterpriseenrollment.yourdomain.com` behind Nginx Proxy Manager, Caddy or Traefik.
2. Edit `docker-compose.yml` and set `KEYSTONE_PUBLIC_URL`, `KEYSTONE_ENROLL_SECRET` and `KEYSTONE_ADMIN_PASSWORD`.
3. Run `docker compose up -d` and point your reverse proxy at port `8080`.
4. Open the dashboard, sign in and go to **Enroll a PC**.

### Settings

| Variable | Required | What it does |
|---|---|---|
| `KEYSTONE_PUBLIC_URL` | yes | HTTPS address PCs use, e.g. `https://enterpriseenrollment.example.com` |
| `KEYSTONE_ENROLL_SECRET` | yes | Password typed on each PC during enrollment |
| `KEYSTONE_ADMIN_PASSWORD` | yes | Dashboard password (user is `admin` unless `KEYSTONE_ADMIN_USER` is set) |
| `KEYSTONE_ORG_NAME` | no | Shown on PCs and in the dashboard |
| `KEYSTONE_DATA_DIR` | no | Where the database and certificate authority live (default `./data`) |
| `KEYSTONE_TLS_CERT` / `KEYSTONE_TLS_KEY` | no | Let Keystone handle TLS itself, which turns on device certificate checks |

**Tip:** if your office email domain is `yourdomain.com`, host Keystone at `enterpriseenrollment.yourdomain.com`. Then Windows finds it automatically when someone types their work email.

## How it works

Windows includes an MDM client that speaks two open Microsoft protocols:

1. **[MS-MDE2] enrollment.** The PC discovers the server, receives a certificate policy, sends a certificate request and gets back a provisioning document. Keystone runs its own small certificate authority and issues each PC a client certificate.
2. **[MS-MDM] / OMA-DM management.** The PC checks in every 15–60 minutes using SyncML. Keystone answers with queued commands (`Get`, `Replace`, `Exec`) and records the results.

```
cmd/keystone      server entry point
internal/wmdm     Windows enrollment + OMA-DM sessions, command catalogue
internal/pki      built-in certificate authority
internal/store    JSON file store
internal/web      admin dashboard
```

## Security notes

- When TLS ends at a reverse proxy, Keystone can't see the PC's client certificate. It then identifies PCs by device ID only. For production, set `KEYSTONE_TLS_CERT`/`KEYSTONE_TLS_KEY` and use TCP passthrough so Keystone verifies every PC's certificate. Support for proxy-forwarded certificates is on the roadmap.
- The enrollment password is shared. Per-user, expiring enrollment codes are on the roadmap.
- Keep `data/pki/ca.key` safe. Anyone who has it can impersonate your server to enrolled PCs.

## Development

```
go test ./...
KEYSTONE_PUBLIC_URL=https://localhost KEYSTONE_ENROLL_SECRET=dev KEYSTONE_ADMIN_PASSWORD=dev go run ./cmd/keystone
```

See [ROADMAP.md](ROADMAP.md) for what's next. Issues and pull requests are welcome.

## License

MIT
