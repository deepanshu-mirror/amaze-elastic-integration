# Push (inbound) Ingest Design — AMaze dispatcher → Elastic

## Goal

The AMaze Elastic package is **push-only** — it does not poll the AMaze REST
API. Instead, the **AMaze integration dispatcher** (which fans high-threat
events out to SOAR / SIEM / webhook endpoints) pushes its **Rich Alert**
payloads directly into Elastic through two inbound data streams:

| Data stream | Input | AMaze dispatcher mode |
|-------------|-------|------------------------|
| `dispatch` | `http_endpoint` | **Webhook mode** — HTTP POST of the Rich Alert JSON |
| `syslog` | `udp` + `tcp` | **Syslog mode** — RFC 3164 message whose `MSG` is the Rich Alert JSON |

The AMaze dispatcher only ever pushes Rich Alert fields (not the ticket/log
fields), so both streams are tuned to the Rich Alert schema. The previous
polling data streams (`alerts`, `audit`, `logs`) and the `httpjson` input were
removed; the package has no dependency on the AMaze API.

## Dispatcher contract (verified)

Source: `mirrormire-amaze/services/amaze-ingest/app/pipeline/dispatcher.py`
and `mirrormire-amaze/services/amaze-core/app/services/integration_svc.py`.

### Payload — `_build_rich_alert()`

```python
_RICH_ALERT_FIELDS = (
    "timestamp", "protocol", "src_ip", "dest_ip", "threat_score", "fraud_score",
    "threat_type", "country", "lat", "lon", "username", "user_agent", "ja3_hash",
    "initial_ttp", "ttp", "site_id", "sca_id", "sca_name", "vm_id",
    "enrichment_details", "logline",
)
# plus: alert_type="neural_event.actionable", schema_version=1,
#       ticket_id (may be None), neural_event_id (may be None)
```

- Webhook mode: `json.dumps(payload, separators=(",", ":"), default=str)`,
  `Content-Type: application/json`, optional auth header (api-key / bearer /
  HMAC `X-AMaze-Signature`).
- Syslog mode (`build_syslog_message`): RFC 3164
  `<134>Apr 21 12:00:00 <hostname> MirrorMire-AMaze: {json}\n` —
  priority 134 = facility local0 (16·8) + severity info (6). Sent over UDP
  (`plain-udp`) or TCP (`plain-tcp`).

### Dispatch criteria

An event is dispatched to an integration when the integration is enabled,
`integration.min_threat_score <= event.threat_score`, and the integration's
`site_id` is `NULL` (global) or matches the event's site. `requires_approval`
integrations are queued rather than pushed.

## Data streams

### `dispatch` — webhook (http_endpoint)

- Listener: `http_endpoint` input, `listen_address` (default `0.0.0.0`),
  `listen_port` (default `8080`), `url_path` (default `/webhook`).
- Body mapped to the **document root** (`prefix: .`); `preserve_original_event`
  keeps the raw JSON in `event.original`.
- Auth: `secret.header`/`secret.value` (covers AMaze `bearer`/`api-key`) and/or
  `hmac.*` (covers AMaze `hmac`).
- Ingest pipeline `default.yml` normalizes the Rich Alert to ECS and preserves
  originals under `amaze.*`. `event.dataset = amaze.dispatch`.

### `syslog` — UDP / TCP

- Two streams in one data stream: `input: udp` and `input: tcp`, each with its
  own template (`udp.yml.hbs`, `tcp.yml.hbs`), default port `514`.
- Stream processors: preserve raw line in `event.original`, then `syslog`
  processor (`format: rfc3164`, `timezone: UTC`).
- Ingest pipeline `default.yml`: JSON-decode `message` into the root (with a
  dissect fallback for a preserved `MirrorMire-AMaze: ` APP-NAME prefix), then
  the same Rich Alert → ECS normalization. `event.dataset = amaze.syslog`.

## ECS mapping (shared by both streams)

| Rich Alert | ECS |
|------------|-----|
| `timestamp` | `@timestamp` |
| `src_ip` | `source.ip` |
| `dest_ip` | `destination.ip` |
| `country` | `source.geo.country_iso_code` |
| `lat`, `lon` | `source.geo.location` (geo_point) |
| `protocol` | `network.protocol` |
| `threat_score` | `event.severity` |
| `ttp` | `threat.technique.id` |
| `threat_type` | `event.action` |
| `username` | `user.name` |
| `user_agent` | `user_agent.original` |
| `logline` | `message` |
| `neural_event_id` | `event.id` |

All originals preserved under `amaze.*`; every document is tagged
`event.kind: alert`, `event.category: [intrusion_detection]`,
`event.module: amaze`.

## AMaze-side configuration

- **Webhook**: integration `type: webhook`,
  `endpoint_url = http://<agent-host>:8080/webhook`. Auth maps to
  `secret_header`/`secret_value` or `hmac_key`.
- **Syslog**: integration `send_method: syslog`,
  `endpoint_url = udp://<agent-host>:514` (plain-udp) or
  `tcp://<agent-host>:514` (plain-tcp).

## Notes / limitations

- The dispatcher hot path (`amaze-ingest`) only sends webhooks; syslog delivery
  lives in `amaze-core` (`integration_svc.py`, `approval_svc.py`,
  `report_dispatcher.py`) but uses the identical `build_syslog_message` format.
- Rich Alert payload does **not** include `dst_ip`-free ticket fields or
  `username`-free log fields; the schema is fixed by `_RICH_ALERT_FIELDS`.
- `ticket_id` / `neural_event_id` may be `null` in the payload (known AMaze
  gap), so `event.id` may be missing; correlate by `src_ip` when needed.
