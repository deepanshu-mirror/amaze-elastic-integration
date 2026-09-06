# MirrorMire AMaze

Receive Rich Alerts that the MirrorMire AMaze dispatcher pushes to SOAR / SIEM
endpoints, with Elastic Agent. No API polling — every high-threat event is
delivered to Elastic in real time as AMaze detects it.

## Data streams

The AMaze integration collects dispatcher-pushed Rich Alerts through two
inbound data streams:

| Data stream | Mode | Source | Description |
|-------------|------|--------|-------------|
| `dispatch` | push (webhook) | AMaze integration dispatcher (HTTP POST) | Rich Alerts pushed by AMaze in webhook mode |
| `syslog` | push (syslog) | AMaze integration dispatcher (UDP/TCP syslog) | Rich Alerts pushed by AMaze in syslog mode |

Both data streams are inbound listeners: Elastic Agent opens an HTTP endpoint
(`dispatch`, webhook mode) and a UDP/TCP syslog listener (`syslog`, syslog
mode), and the AMaze dispatcher fans out every matching high-threat event to
them in real time. See
[Rich Alert dispatch (webhook and syslog)](./rich-alert-dispatch.md) for the
exact payload schema and the AMaze-side configuration.

## Requirements

- Elastic Stack 8.x with Elastic Agent and Fleet.
- A MirrorMire AMaze deployment with the integration dispatcher enabled
  (outbound webhook and/or syslog integrations).

## Setup

1. In Kibana, open **Integrations** and search for **AMaze**.
2. Click **Add AMaze**.
3. Enable the data streams you need and configure each listener:

   | Data stream | Settings |
   |-------------|----------|
   | `dispatch` | `listen_address` (default `0.0.0.0`), `listen_port` (default `8080`), `url_path` (default `/webhook`); optional `secret_header`/`secret_value` or `hmac_key` to validate AMaze auth headers |
   | `syslog` | `listen_address` (default `0.0.0.0`) and `listen_port` (default `514`) for the UDP and/or TCP stream |

4. Save the policy and enroll an Elastic Agent.

### Point AMaze at the agent

- **Webhook mode** — configure the AMaze integration with
  `endpoint_url = http://<agent-host>:<listen_port><url_path>` (default
  `http://<agent-host>:8080/webhook`). Use `secret_header`/`secret_value` for
  AMaze bearer or api-key mode, or `hmac_key` for AMaze HMAC mode.
- **Syslog mode** — configure the AMaze integration with
  `endpoint_url = udp://<agent-host>:<port>` or `tcp://<agent-host>:<port>`
  (default port `514`).

## ECS mapping

Events are normalized to ECS. Original AMaze values are preserved in the
`amaze.*` namespace so no data is lost during transformation.

| Rich Alert field | ECS field |
|------------------|-----------|
| `timestamp` | `@timestamp` |
| `src_ip` | `source.ip` |
| `dest_ip` | `destination.ip` |
| `country` | `source.geo.country_iso_code` |
| `lat` / `lon` | `source.geo.location` |
| `protocol` | `network.protocol` |
| `threat_score` | `event.severity` |
| `ttp` | `threat.technique.id` |
| `threat_type` | `event.action` |
| `username` | `user.name` |
| `user_agent` | `user_agent.original` |
| `logline` | `message` |
| `neural_event_id` | `event.id` |

All original values remain available under `amaze.*`, e.g. `amaze.alert_type`,
`amaze.schema_version`, `amaze.ticket_id`, `amaze.neural_event_id`,
`amaze.threat_score`, `amaze.fraud_score`, `amaze.threat_type`, `amaze.src_ip`,
`amaze.dest_ip`, `amaze.country`, `amaze.lat`, `amaze.lon`, `amaze.username`,
`amaze.user_agent`, `amaze.ja3_hash`, `amaze.initial_ttp`, `amaze.ttp`,
`amaze.site_id`, `amaze.sca_id`, `amaze.sca_name`, `amaze.vm_id`,
`amaze.enrichment_details`, and `amaze.logline`.

## Troubleshooting

- **No documents arriving** — verify the AMaze integration's
  `endpoint_url` points at the correct agent host, port, and path, and check
  the agent's logs. For `dispatch`, enable `preserve_original_event` and
  inspect `event.original` to confirm the payload shape.
- **Webhook rejected (401/403)** — the `secret_header`/`secret_value` (or
  `hmac_key`) does not match what the AMaze integration is configured to send.
- **Syslog events not parsed** — confirm the AMaze integration uses
  `send_method: syslog` with `payload_type` `plain-udp` (UDP stream) or
  `plain-tcp` (TCP stream), and that the listener port is open.
- **Self-signed TLS errors** — for a TLS-terminated webhook, configure the
  `ssl` settings on the `dispatch` data stream.
