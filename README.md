# minivpn_rust 🦀🔒

A lightweight, secure, asynchronous Hub-and-Spoke virtual private network (VPN) built from scratch in Rust. It utilizes the **`Noise_IK`** handshake protocol (via the `snow` crate) for static peer authentication over UDP, manages virtual network interfaces using `tokio` and `tun`, and parses configuration files via `toml` and `serde`.

## Features
- **Modern Async Architecture**: Powered by `tokio` for high-throughput, non-blocking I/O.
- **Cryptographic Authentication**: Uses `Noise_IK_25519_ChaChaPoly_SHA256` to ensure unauthenticated peers cannot connect or probe the network.
- **Configuration-Driven**: Clean TOML-based setup for both Hub and Spoke nodes.
- **Cross-Platform Foundation**: Built for Linux TUN/TAP network interfaces.

---

## Getting Started

### Prerequisites
- Rust (Edition 2021+)
- Linux environment with root/sudo privileges (required for TUN interface creation and routing).

### 1. Clone & Build
```bash
git clone [https://github.com/DiggyDiggyGraves/minivpn_rust.git](https://github.com/DiggyDiggyGraves/minivpn_rust.git)
cd minivpn_rust
cargo build --release
```

### 2. Configure the Hub
Copy the example hub configuration:
```bash
cp hub.example.toml hub.toml
```

Run the Hub server (Terminal 1):
```bash
sudo ./target/release/minivpn_rust --server --config hub.toml
```
*Note: The hub will output its **Static Public Key (hex)** upon startup. Copy this key.*

### 3. Configure the Spoke
Copy the example spoke configuration:
```bash
cp spoke.example.toml spoke.toml
```
Open `spoke.toml` and paste the hub's public key hex into the `hub_pubkey` field.

Run the Spoke client (Terminal 2):
```bash
sudo ./target/release/minivpn_rust --config spoke.toml
```

### 4. Test the Tunnel
From your spoke terminal or a separate window, verify the connection:
```bash
ping 10.0.0.1
```

---

## License
Licensed under the [MIT License](LICENSE).
