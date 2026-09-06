# Rich Alert dispatch (webhook and syslog)

AMaze fans out every matching high-threat event to its configured outbound
integrations (SOAR / SIEM / webhook). Each outbound attempt carries a **Rich
Alert**: a compact, versioned projection of the enriched neural event that is
independent of the internal database schema.

The AMaze package's `dispatch` and `syslog` data streams receive those Rich
Alerts *inbound*, so the same detections that AMaze pushes to a SIEM like
Wazuh or a SOAR like Shuffle can land in Elastic Security with zero polling
latency.

The AMaze dispatcher supports two delivery modes:

- **Webhook mode** — an HTTP `POST` whose JSON body is the Rich Alert.
- **Syslog mode** — an RFC 3164 syslog message whose `MSG` part is the Rich
  Alert JSON, sent over UDP (`plain-udp`) or TCP (`plain-tcp`).

The `dispatch` data stream covers webhook mode; the `syslog` data stream
covers syslog mode.

## Rich Alert schema

The dispatcher always emits the same field set (`_RICH_ALERT_FIELDS`), plus
`alert_type`, `schema_version`, `ticket_id`, and `neural_event_id`. Fields
that are `NULL` on the source event are still present in the JSON, set to
`null`.

| Field | Type | Description |
|-------|------|-------------|
| `alert_type` | string | Always `neural_event.actionable` |
| `schema_version` | integer | Outbound schema version (currently `1`) |
| `ticket_id` | string \| null | AMaze ticket UUID, may be `null` |
| `neural_event_id` | string \| null | AMaze neural event UUID, may be `null` |
| `timestamp` | string | Event timestamp (ISO 8601, UTC) |
| `protocol` | string | Network protocol, e.g. `ssh` |
| `src_ip` | string \| null | Source IP |
| `dest_ip` | string \| null | Destination IP |
| `threat_score` | integer \| null | 0–100 AMaze threat score |
| `fraud_score` | integer \| null | 0–100 fraud score |
| `threat_type` | string \| null | Human-readable classification, e.g. `brute_force` |
| `country` | string \| null | ISO country code of the source IP |
| `lat` | number \| null | Latitude of the source IP |
| `lon` | number \| null | Longitude of the source IP |
| `username` | string \| null | Username observed in the activity |
| `user_agent` | string \| null | User agent observed in the activity |
| `ja3_hash` | string \| null | JA3 TLS fingerprint hash |
| `initial_ttp` | array | MITRE ATT&CK techniques at initial access, e.g. `["T1110"]` |
| `ttp` | string \| null | MITRE ATT&CK technique, e.g. `T1110` |
| `site_id` | string \| null | Site UUID the event belongs to |
| `sca_id` | string \| null | Stable SCA product identifier |
| `sca_name` | string \| null | SCA display label |
| `vm_id` | string \| null | Honeypot / VM identifier that captured the activity |
| `enrichment_details` | object | Per-source enrichment results (`ipqs`, `abuseipdb`, `virustotal`, …) |
| `logline` | string \| null | Raw sensor log line |

Only Rich Alert fields are pushed — ticket and log fields are not included in
the outbound payload.

## Dispatch data stream (webhook mode)

The `dispatch` data stream starts an `http_endpoint` listener that accepts
AMaze webhook `POST`s. The JSON body is mapped to the root of the document and
normalized to ECS by the ingest pipeline.

### Configure the data stream

| Setting | Default | Description |
|---------|---------|-------------|
| `listen_address` | `0.0.0.0` | Interface the webhook listener binds to |
| `listen_port` | `8080` | TCP port the listener accepts `POST`s on |
| `url_path` | `/webhook` | URL path the listener responds to |
| `secret_header` / `secret_value` | empty | Validate a static header (AMaze `bearer` / `api-key` mode) |
| `hmac_key` | empty | Validate AMaze `hmac` signatures (`X-AMaze-Signature`, SHA-256) |
| `preserve_original_event` | `true` | Keep the raw JSON body in `event.original` |

### Point AMaze at the listener

In the AMaze dashboard, create or edit an integration with `type: webhook`
and set:

```text
endpoint_url = http://<elastic-agent-host>:8080/webhook
```

AMaze's webhook auth modes map to the Elastic side as follows:

| AMaze mode | Elastic settings |
|------------|------------------|
| `none` | no secret / hmac settings |
| `api-key` | `secret_header` = the header AMaze sends (e.g. `X-AMaze-Api-Key`), `secret_value` = the API key |
| `bearer` / `jwt` | `secret_header` = `Authorization`, `secret_value` = `Bearer <token>` |
| `hmac` | `hmac_key` = the shared secret (default `X-AMaze-Signature`, SHA-256) |

## Syslog data stream (syslog mode)

The `syslog` data stream starts a UDP and/or TCP listener (RFC 3164). The
syslog processor strips the header, the ingest pipeline decodes the JSON
`MSG`, and the Rich Alert is normalized to ECS. The parsed syslog header is
kept under `log.syslog.*` (facility `local0` / priority `134` / severity
`info` for AMaze dispatches).

### Configure the data stream

Enable either the UDP or TCP stream (or both) and set:

| Setting | Default | Description |
|---------|---------|-------------|
| `listen_address` | `0.0.0.0` | Interface the listener binds to |
| `listen_port` | `514` | UDP / TCP port |
| `format` | `rfc3164` | Syslog format emitted by AMaze |
| `timezone` | `UTC` | Timezone for the syslog header timestamp (AMaze emits UTC) |
| `preserve_original_event` | `true` | Keep the raw syslog line in `event.original` |

> **Note:** ports below 1024 (e.g. `514`) require Elastic Agent to run with
> sufficient privileges to bind them.

### Point AMaze at the listener

Create or edit an AMaze integration with `send_method: syslog` and set:

```text
endpoint_url = udp://<elastic-agent-host>:514     # plain-udp
endpoint_url = tcp://<elastic-agent-host>:514     # plain-tcp
```

## Example webhook payload

```json
{
  "alert_type": "neural_event.actionable",
  "schema_version": 1,
  "ticket_id": "22222222-2222-2222-2222-222222222222",
  "neural_event_id": "33333333-3333-3333-3333-333333333333",
  "timestamp": "2026-04-21T12:00:00Z",
  "protocol": "ssh",
  "src_ip": "203.0.113.42",
  "dest_ip": "10.0.0.5",
  "threat_score": 95,
  "fraud_score": 88,
  "threat_type": "brute_force",
  "country": "CN",
  "lat": 31.2304,
  "lon": 121.4737,
  "username": "root",
  "user_agent": "OpenSSH_9.0",
  "ja3_hash": "6734f3f4b6f9a2c8d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
  "initial_ttp": ["T1110"],
  "ttp": "T1110",
  "site_id": "11111111-1111-1111-1111-111111111111",
  "sca_id": "44444444-4444-4444-4444-444444444444",
  "sca_name": "ssh_sca",
  "vm_id": "vm-ssh-honeypot-1",
  "enrichment_details": {
    "ipqs": {
      "fraud_score": 88
    }
  },
  "logline": "brute force attempt"
}
```

In syslog mode the same payload is wrapped as:

```text
<134>Apr 21 12:00:00 <hostname> MirrorMire-AMaze: { "alert_type": "neural_event.actionable", ... }
```

## ECS mapping

| Rich Alert field | ECS field |
|------------------|-----------|
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

All original values are preserved under `amaze.*` (e.g. `amaze.threat_score`,
`amaze.src_ip`, `amaze.initial_ttp`, `amaze.enrichment_details`), and every
document is tagged `event.kind: alert`, `event.category: intrusion_detection`,
`event.module: amaze`, and `event.dataset: amaze.dispatch` or `amaze.syslog`.
