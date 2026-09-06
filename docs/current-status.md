# AMaze Elastic Integration Status

## Project Summary

This project builds a native Elastic Integration Package for MirrorMire AMaze.

The integration is **push-only**: it receives **Rich Alerts** that the AMaze
integration dispatcher pushes out to SOAR / SIEM endpoints — over HTTP webhook
(`dispatch` data stream) and UDP/TCP syslog (`syslog` data stream). There is
no dependency on polling the AMaze REST API.

---

## Completed

### Package Implementation

- Package Manifest
- Changelog
- Dispatch Data Stream (webhook / `http_endpoint`)
- Syslog Data Stream (UDP + TCP)
- Rich Alert → ECS ingest pipelines
- Package Icons (`img/amaze-logo.png`, `img/amaze-logo-wordmark.png`)
- Rich Alerts Overview Dashboard (`kibana/dashboard/amaze-dispatch-overview.json`)

### Data Processing

- Rich Alert ECS Field Definitions
- Sample Rich Alert events (`dispatch`, `syslog`)
- Ingest Pipeline Design (webhook + syslog)

### Validation

- elastic-package v0.126.0 installed from official GitHub release
- `elastic-package lint` PASSED
- `elastic-package build` PASSED → `build/packages/amaze-1.0.0.zip`

---

## Data Streams

### Dispatch (webhook)

Input: `http_endpoint`

Purpose:

Receive AMaze Rich Alerts pushed over HTTP webhook (webhook mode). Listens on
`listen_address:listen_port` (default `0.0.0.0:8080`) at `url_path` (default
`/webhook`); the JSON body is mapped to the document root and normalized to
ECS. Optional header/HMAC auth validation.

### Syslog (UDP / TCP)

Input: `udp` + `tcp`

Purpose:

Receive AMaze Rich Alerts pushed over syslog (syslog mode). RFC 3164 messages
(`<134> ... MirrorMire-AMaze: {json}`) are parsed, the JSON `MSG` is decoded,
and the Rich Alert is normalized to ECS. Default port `514`.

---

## ECS Mapping Highlights

| Rich Alert Field | ECS Field |
|------------|------------|
| src_ip | source.ip |
| dest_ip | destination.ip |
| protocol | network.protocol |
| threat_score | event.severity |
| ttp | threat.technique.id |
| threat_type | event.action |
| username | user.name |
| user_agent | user_agent.original |
| logline | message |
| timestamp | @timestamp |

All originals preserved under `amaze.*`; documents tagged
`event.kind: alert`, `event.category: intrusion_detection`,
`event.module: amaze`, `event.dataset: amaze.dispatch` / `amaze.syslog`.

---

## Validation Status

Status: PASSED (reproducible with real tooling)

Commands:

```bash
elastic-package lint
elastic-package build
```

- `elastic-package lint` and `elastic-package build` are installed from the official
  [elastic-package](https://github.com/elastic/elastic-package) release `v0.126.0`.
- Lint output: `Done` (clean).
- Build output: `build/packages/amaze-1.0.0.zip` (includes `img/` and `kibana/dashboard/`).

---

## Package Assets

### Icon

- `img/amaze-logo.png` (emblem) and `img/amaze-logo-wordmark.png`, registered in `manifest.yml` under `icons`.

### Dashboard

- `kibana/dashboard/amaze-dispatch-overview.json` — **AMaze Rich Alerts Overview**.
- Modern by-value panels (Lens + Markdown), filtered to `data_stream.dataset: amaze.dispatch`.
- Panels: alerts by action (donut), alerts over time (bar), top MITRE ATT&CK techniques (table), and a welcome markdown panel.
- Follows the package-spec v3 requirements: by-value visualizations (SVR00004), dashboard filter present (SVR00001/SVR00002), no dangling object IDs (SVR00003).

---

## Recommended Next Steps (before registry publishing)

- Run `elastic-package test` against a live stack (requires Docker) to verify the ingest pipelines and dashboard rendering end-to-end.
- When MirrorMire obtains an **Elastic partnership**, switch `owner.type` in `package/manifest.yml` from `community` to `partner` (requires an actual partnership — left as `community` for now).
- Add a `_dev/` folder with system tests before publishing to the public registry.
