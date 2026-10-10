use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use snow::TransportState;
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "tun0")]
    tun_name: String,
    #[arg(long, default_value = "10.0.0.1")]
    local_ip: std::net::Ipv4Addr,
    #[arg(long, default_value = "10.0.0.2")]
    remote_ip: std::net::Ipv4Addr,
    #[arg(long, default_value_t = 50001)]
    bind_port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    peer_host: String,
    #[arg(long, default_value_t = 50002)]
    peer_port: u16,
    #[arg(long, default_value_t = false)]
    initiator: bool,
}

async fn perform_handshake(
    socket: &UdpSocket, 
    peer_addr: SocketAddr, 
    is_initiator: bool
) -> Result<TransportState, Box<dyn std::error::Error>> {
    let mut handshake_buffer = [0u8; 1024];
    let mut payload_buffer = [0u8; 1024];

    let transport_state = if is_initiator {
        println!("[*] Starting Noise handshake (Initiator)...");
        let mut state = snow::Builder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse()?)
            .build_initiator()?;
        
        let len = state.write_message(&[], &mut handshake_buffer)?;
        socket.send_to(&handshake_buffer[..len], peer_addr).await?;

        let (n, _) = socket.recv_from(&mut handshake_buffer).await?;
        state.read_message(&handshake_buffer[..n], &mut payload_buffer)?;

        state.into_transport_mode()?
    } else {
        println!("[*] Starting Noise handshake (Responder)...");
        let mut state = snow::Builder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse()?)
            .build_responder()?;

        let (n, _) = socket.recv_from(&mut handshake_buffer).await?;
        state.read_message(&handshake_buffer[..n], &mut payload_buffer)?;

        let len = state.write_message(&[], &mut handshake_buffer)?;
        socket.send_to(&handshake_buffer[..len], peer_addr).await?;

        state.into_transport_mode()?
    };

    println!("[+] Noise cryptographic handshake successful! Transport ciphers active.");
    Ok(transport_state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    let bind_addr = format!("0.0.0.0:{}", args.bind_port);
    let socket = UdpSocket::bind(&bind_addr).await?;
    let peer_addr: SocketAddr = format!("{}:{}", args.peer_host, args.peer_port).parse()?;
    println!("[*] Bound UDP socket to {}, target peer: {}", bind_addr, peer_addr);

    let transport = perform_handshake(&socket, peer_addr, args.initiator).await?;
    let transport_tx = Arc::new(tokio::sync::Mutex::new(transport));
    let transport_rx = transport_tx.clone();

    let mut config = tun::Configuration::default();
    config
        .tun_name(&args.tun_name)
        .address(args.local_ip)
        .destination(args.remote_ip)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    let dev = tun::create_as_async(&config)?;
    println!("[*] TUN interface {} active: Local {} <-> Remote {}", 
             args.tun_name, args.local_ip, args.remote_ip);

    let dev = Arc::new(dev);
    let dev_clone = dev.clone();
    let socket = Arc::new(socket);
    let socket_tx = socket.clone();
    let socket_rx = socket;

    // Task A: OS TUN Stack -> Encrypt (Snow Transport) -> UDP Send
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut out_buf = vec![0u8; 2048];
        loop {
            match dev_clone.recv(&mut buf).await {
                Ok(n) if n > 0 => {
                    let packet = &buf[..n];
                    let mut tr = transport_tx.lock().await;
                    
                    if let Ok(len) = tr.write_message(packet, &mut out_buf) {
                        let _ = socket_tx.send_to(&out_buf[..len], peer_addr).await;
                    }
                }
                _ => break,
            }
        }
    });

    // Task B: UDP Receive -> Decrypt (Snow Transport) -> OS TUN Stack
    let mut buf = vec![0u8; 2048];
    let mut out_buf = vec![0u8; 2048];
    loop {
        match socket_rx.recv_from(&mut buf).await {
            Ok((n, _addr)) if n > 0 => {
                let data = &buf[..n];
                let mut tr = transport_rx.lock().await;

                if let Ok(len) = tr.read_message(data, &mut out_buf) {
                    let decrypted = &out_buf[..len];
                    let _ = dev.send(decrypted).await;
                }
            }
            _ => {}
        }
    }
}
