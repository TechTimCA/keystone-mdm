# Roadmap

## v0.1: Prototype (now)
- [x] Windows enrollment (discovery, policy, certificate enrollment)
- [x] OMA-DM check-ins with a command queue
- [x] Inventory and health: BitLocker, antivirus, firewall
- [x] Dashboard with one-click actions
- [ ] **Verified on a real Windows 11 Pro PC**
- [ ] Docker image published to GHCR

## v0.2: Useful for one office
- [ ] Policy profiles: apply a set of settings to groups of PCs, not one at a time
- [ ] Plain-English policy library: screen lock, USB blocking, update rings, Defender settings
- [ ] App installs and updates with winget (Chrome, Zoom, Adobe Reader, Office...)
- [ ] Per-user, expiring enrollment codes
- [ ] Proxy-forwarded client certificates (Nginx Proxy Manager, Caddy, Traefik)
- [ ] Remote wipe and "reset this PC"
- [ ] SQLite storage

## v0.3: Hand it to an office manager
- [ ] Starter templates: "Dental office", "Accounting firm", "Home/family"
- [ ] Email alerts when a PC goes red
- [ ] Compliance report PDF (for cyber insurance questionnaires)
- [ ] Instant commands with Windows Push Notification Service (no waiting for check-in)
- [ ] Sign in with Microsoft or Google

## Later
- Multi-client mode for MSPs
- Remote desktop (MeshCentral integration)
- macOS and mobile
