# nospoon

> *"There is no spoon."* — The Matrix (1999)

## Install

```bash
sudo npm install -g nospoon
```

## HTTP control plane

```bash
sudo nospoon
```

## Command reference

### Control plane options

| Flag | Default | Description |
|------|---------|-------------|
| `--port <num>` | `80` | HTTP listen port |
| `--host <addr>` | auto loopback alias | Bind address (`nospoon` DNS name when mesh DNS is on) |
| `--primary-cidr <cidr>` | auto `10.0.x.1/24` | Primary (direct pool) IPv4 CIDR |
| `--seed <z32|hex>` | `~/.nospoon/identity.json` | Control-plane Noise seed |
| `--no-system-dns` | off | Skip OS resolver override |

## License

GPL-3.0 — See [LICENSE](LICENSE)

## Credits

- [HyperDHT](https://github.com/holepunchto/hyperdht) — DHT and hole-punching
- [Hyperswarm](https://github.com/holepunchto/hyperswarm) — Topic-based peer discovery
- [koffi](https://koffi.dev/) — FFI for TUN on Linux / macOS
- [Noise Protocol](https://noiseprotocol.org/) — Encryption framework
- [HoleSail](https://holesail.io/) — Layer-4 inspiration
