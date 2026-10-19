use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use snow::TransportState;
use clap::Parser;
use serde::Deserialize;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config: String,
    #[arg(long, default_value_t = false)]
    server: bool,
}

#[derive(Deserialize, Debug)]
struct HubConfig {
    tun_name: String,
    local_ip: std::net::Ipv4Addr,
    remote_ip: std::net::Ipv4Addr,
    bind_port: u16,
}

#[derive(Deserialize, Debug)]
struct SpokeConfig {
    tun_name: String,
    local_ip: std::net::Ipv4Addr,
    remote_ip: std::net::Ipv4Addr,
    bind_port: u16,
    peer_host: String,
    peer_port: u16,
    hub_pubkey: String,
}

#[derive(Deserialize, Debug)]
struct ConfigFile {
    hub: Option<HubConfig>,
    spoke: Option<SpokeConfig>,
}

fn extract_dest_ip(packet: &[u8]) -> Option<std::net::Ipv4Addr> {
    if packet.len() >= 20 {
        Some(std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
    } else {
        None
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config_content = std::fs::read_to_string(&args.config)
        .unwrap_or_else(|_| panic!("Failed to read configuration file: {}", args.config));
    let config_file: ConfigFile = toml::from_str(&config_content)?;

    let noise_params = "Noise_IK_25519_ChaChaPoly_SHA256".parse()?;

    if args.server {
        let cfg = config_file.hub.expect("Missing [hub] section in configuration file");
        
        let bind_addr = format!("0.0.0.0:{}", cfg.bind_port);
        let socket = UdpSocket::bind(&bind_addr).await?;
        let socket = Arc::new(socket);
        println!("[*] Bound Hub UDP socket to {}", bind_addr);

        let mut tun_config = tun::Configuration::default();
        tun_config
            .name(&cfg.tun_name)
            .address(cfg.local_ip)
            .destination(cfg.remote_ip)
            .up();

        let dev = tun::create_as_async(&tun_config)?;
        println!("[*] TUN interface {} active: Local {} <-> Remote {}", 
                 cfg.tun_name, cfg.local_ip, cfg.remote_ip);
        let dev = Arc::new(Mutex::new(dev));

        println!("[*] Running in HUB mode with Noise_IK authentication...");

        let builder = snow::Builder::new(noise_params);
        let keypair = builder.generate_keypair()?;
        println!("[*] Hub Static Public Key (hex): {}", hex::encode(&keypair.public));

        type PeerTable = Arc<RwLock<HashMap<std::net::Ipv4Addr, (SocketAddr, Arc<Mutex<TransportState>>)>>>;
        let routing_table: PeerTable = Arc::new(RwLock::new(HashMap::new()));

        let socket_rx = socket.clone();
        let socket_tx_1 = socket.clone();
        let socket_tx_2 = socket.clone();
        let dev_rx = dev.clone();
        let dev_tx = dev.clone();
        let table_for_recv = routing_table.clone();
        let table_for_tun = routing_table.clone();
        let hub_private_key = keypair.private;

        // Task 1: Inbound UDP from Spokes -> Decrypt -> TUN Write
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut out_buf = vec![0u8; 2048];
            loop {
                match socket_rx.recv_from(&mut buf).await {
                    Ok((n, client_addr)) => {
                        let packet_data = &buf[..n];

                        let mut found_transport = None;
                        {
                            let table = table_for_recv.read().await;
                            for (_ip, (addr, transport)) in table.iter() {
                                if *addr == client_addr {
                                    found_transport = Some(transport.clone());
                                    break;
                                }
                            }
                        }

                        if let Some(transport) = found_transport {
                            let mut tr = transport.lock().await;
                            if let Ok(len) = tr.read_message(packet_data, &mut out_buf) {
                                let decrypted = &out_buf[..len];
                                let mut dev_lock = dev_rx.lock().await;
                                let _ = dev_lock.write_all(decrypted).await;
                            }
                        } else {
                            println!("[*] Incoming authenticated connection from {}.", client_addr);
                            let builder = snow::Builder::new("Noise_IK_25519_ChaChaPoly_SHA256".parse().unwrap());
                            let mut state = builder
                                .local_private_key(&hub_private_key)
                                .build_responder().unwrap();
                            
                            let mut payload_buf = [0u8; 1024];
                            if state.read_message(packet_data, &mut payload_buf).is_ok() {
                                let mut handshake_res_buf = [0u8; 1024];
                                if let Ok(len) = state.write_message(&[], &mut handshake_res_buf) {
                                    let _ = socket_tx_1.send_to(&handshake_res_buf[..len], client_addr).await;
                                    if let Ok(transport) = state.into_transport_mode() {
                                        println!("[+] Noise_IK Handshake successful with client at {}", client_addr);
                                        let client_ip = std::net::Ipv4Addr::new(10, 0, 0, 2);
                                        let mut table = table_for_recv.write().await;
                                        table.insert(client_ip, (client_addr, Arc::new(Mutex::new(transport))));
                                    }
                                }
                            } else {
                                println!("[-] Handshake failed: unauthorized client at {}", client_addr);
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Task 2: Outbound TUN Read -> Encrypt -> Spoke UDP
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut out_buf = vec![0u8; 2048];
            loop {
                let n = {
                    let mut dev_lock = dev_tx.lock().await;
                    match dev_lock.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => break,
                    }
                };

                if n > 0 {
                    let packet = &buf[..n];
                    if let Some(dest_ip) = extract_dest_ip(packet) {
                        let target_peer = {
                            let table = table_for_tun.read().await;
                            table.get(&dest_ip).map(|(addr, tr)| (*addr, tr.clone()))
                        };

                        if let Some((peer_addr, transport)) = target_peer {
                            let mut tr = transport.lock().await;
                            if let Ok(len) = tr.write_message(packet, &mut out_buf) {
                                let _ = socket_tx_2.send_to(&out_buf[..len], peer_addr).await;
                            }
                        }
                    }
                }
            }
        });

        tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;

    } else {
        let cfg = config_file.spoke.expect("Missing [spoke] section in configuration file");

        let bind_addr = format!("0.0.0.0:{}", cfg.bind_port);
        let socket = UdpSocket::bind(&bind_addr).await?;
        let socket = Arc::new(socket);
        println!("[*] Bound Spoke UDP socket to {}", bind_addr);

        let mut tun_config = tun::Configuration::default();
        tun_config
            .name(&cfg.tun_name)
            .address(cfg.local_ip)
            .destination(cfg.remote_ip)
            .up();

        let dev = tun::create_as_async(&tun_config)?;
        println!("[*] TUN interface {} active: Local {} <-> Remote {}", 
                 cfg.tun_name, cfg.local_ip, cfg.remote_ip);
        let dev = Arc::new(Mutex::new(dev));

        let peer_addr: SocketAddr = format!("{}:{}", cfg.peer_host, cfg.peer_port).parse()?;
        println!("[*] Connecting to Hub at {} as Spoke with Noise_IK...", peer_addr);

        let hub_pub_bytes = hex::decode(cfg.hub_pubkey)?;

        let builder = snow::Builder::new(noise_params.clone());
        let client_keypair = builder.generate_keypair()?;

        let mut state = snow::Builder::new(noise_params)
            .local_private_key(&client_keypair.private)
            .remote_public_key(&hub_pub_bytes)
            .build_initiator()?;

        let mut handshake_buffer = [0u8; 1024];
        let mut payload_buffer = [0u8; 1024];

        let len = state.write_message(&[], &mut handshake_buffer)?;
        socket.send_to(&handshake_buffer[..len], peer_addr).await?;

        let (n, _) = socket.recv_from(&mut handshake_buffer).await?;
        state.read_message(&handshake_buffer[..n], &mut payload_buffer)?;

        let transport = state.into_transport_mode()?;
        let transport_tx = Arc::new(Mutex::new(transport));
        let transport_rx = transport_tx.clone();
        println!("[+] Authenticated secure connection established with Hub!");

        let dev_clone = dev.clone();
        let socket_tx = socket.clone();
        let socket_rx = socket;

        // Task A: Spoke TUN Read -> Encrypt -> Hub UDP
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut out_buf = vec![0u8; 2048];
            loop {
                let n = {
                    let mut dev_lock = dev_clone.lock().await;
                    match dev_lock.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => break,
                    }
                };

                if n > 0 {
                    let packet = &buf[..n];
                    let mut tr = transport_tx.lock().await;
                    if let Ok(len) = tr.write_message(packet, &mut out_buf) {
                        let _ = socket_tx.send_to(&out_buf[..len], peer_addr).await;
                    }
                }
            }
        });

        // Task B: Hub UDP -> Decrypt -> Spoke TUN Write
        let mut buf = vec![0u8; 2048];
        let mut out_buf = vec![0u8; 2048];
        loop {
            match socket_rx.recv_from(&mut buf).await {
                Ok((n, _)) if n > 0 => {
                    let data = &buf[..n];
                    let mut tr = transport_rx.lock().await;
                    if let Ok(len) = tr.read_message(data, &mut out_buf) {
                        let mut dev_lock = dev.lock().await;
                        let _ = dev_lock.write_all(&out_buf[..len]).await;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}
