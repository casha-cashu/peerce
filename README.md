# peerce

Direct P2P file/folder transfer over the internet. No clouds, no relays for data.
QUIC (`quinn`, TLS 1.3) over UDP, `tar` + `zstd` streaming, `BLAKE3` integrity,
3-word pairing codes, Cloudflare Worker rendezvous, STUN NAT discovery.

## CLI

```bash
# Send file or folder (compressed by default). Prints a pairing code.
peerce send ./dataset --signal https://peerce-signal.tmisa7398.workers.dev
# -> Pairing code: orbit-falcon-neon
# -> Waiting for peer... Connected!

# Receive
peerce get orbit-falcon-neon --signal https://peerce-signal.tmisa7398.workers.dev --out .
# -> receiving: dataset [dir]

# Options
peerce send ./f.bin --no-compress        # raw transfer
peerce send ./f.bin --port 4000          # fixed local UDP port (firewall-friendly)
peerce get <code> --port 4000 --out /tmp/in
peerce send ./f.bin --direct 192.168.0.108:4000 --peer-fp <hex>  # LAN, no signaling
peerce send ./f.bin --direct 192.168.0.108:4000 --raw-v1        # compat with old binaries
peerce recv --bind 0.0.0.0:4000 --out .  # legacy direct listener
peerce rendezvous --bind 127.0.0.1:9500  # local signaling stub (same HTTP API as worker)
peerce route 8.8.8.8                     # check egress: direct or via VPN
```

## Direct route (no VPN tunnel)

Bulk P2P traffic and STUN must NOT go through a VPN tunnel:

- The CLI auto-binds to the physical interface IP (ignores `tun_*`, `tailscale*`,
  `wg*`, carrier-grade NAT ranges). Override with `--bind-ip`.
- Before connecting, the CLI checks `ip route get <peer>`. If the route goes via
  a tunnel, it aborts and prints the exact bypass command:
  `sudo ip route add <peer>/32 via <gw> dev <iface>`.
  Override with `--via-vpn` (not recommended for data).
- Private LAN ranges normally bypass tunnels automatically.
- Signaling (HTTPS to the Worker) may go via VPN. Only STUN + QUIC data stay direct.

## Firewall

The receiver's UDP port must be reachable. Either open one fixed port once:

```bash
peerce get <code> --port 4000
sudo ufw allow 4000/udp
```

or (LAN test only) open the ephemeral range. The sender needs no inbound rules
on cone NATs; hole punching sends first.

## Signaling protocol (shared by `rendezvous` stub and Worker)

- `POST /v1/rooms {code, addr, fp}` → `{"ok":true}` (sender registers reflexive addr + cert fingerprint)
- `POST /v1/rooms/{code}/join {addr, fp}` → `{"peer_addr","peer_fp"}` (receiver gets sender)
- `GET /v1/rooms/{code}` → `{"peer_addr","peer_fp"}` once joined, else `404 {"waiting":true}`.
  The room is deleted after the exchange. Rooms expire after 5 minutes.

## Wire protocol

- `PRC1` + name + size + raw bytes + `BLAKE3-32` (legacy, `--raw-v1` / old binaries).
- `PRC` + ver(`1`=raw, `2`=zstd) + flags(bit0 compress, bit1 is_dir) + name + orig size,
  then frames `[len u32be][payload]` … `[0xFFFFFFFF][BLAKE3-32 of original bytes]`.
  Dirs travel as a live `tar` stream, compressed per chunk, never fully in RAM or on disk.
- QUIC server cert is ephemeral per transfer. The client pins the
  `BLAKE3(cert DER)` fingerprint received via signaling (TOFU). Mismatch aborts.
  `--direct` without `--peer-fp` is unauthenticated (LAN tests only).

## Worker deploy

```bash
cd worker && npm i && npx wrangler login && npm run deploy
# use the printed https://peerce-signal.<you>.workers.dev as --signal
```

To give the agent deploy access, either:

1. Create a token at `dash.cloudflare.com → My Profile → API Tokens → Create Token`
   (template "Edit Cloudflare Workers"), then share `CLOUDFLARE_API_TOKEN`,
   `CLOUDFLARE_ACCOUNT_ID`, and the desired worker name. The agent runs
   `CLOUDFLARE_API_TOKEN=... npx wrangler deploy` locally. Revoke the token after.
2. Or deploy yourself with the commands above and just share the worker URL.

## Status

Working: direct LAN, signaling via stub, fingerprint, compress, dirs, hole-punch
probes, symmetric-NAT failure message. Next: WebSocket push for instant
"peer joined", mutual client-cert check, resume, IPv6.
