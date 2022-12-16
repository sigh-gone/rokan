use crate::host_discover::{get_all_ips, get_ip};
use crate::scnr_records::{
    BannerRecord, CommonBannerRecord, CommonScanRecord, DropBox, ScanRecord,
};
use pnet_packet::Packet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use std::str::FromStr;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use pnet::packet::tcp::MutableTcpPacket;
use pnet_datalink;

pub struct DropBoxScnr {}

impl DropBoxScnr {
    pub async fn from_file(file_name: &str) -> Result<Vec<CommonScanRecord>, &str> {
        let mut file = File::open(file_name).await.expect("could not open file");
        let mut data = String::new();

        file.read_to_string(&mut data)
            .await
            .expect("could not open read to string");

        let records = DropBoxScnr::from_string(data)
            .await
            .expect("dropboxscnr failure");

        Ok(records)
    }

    pub async fn from_string(db_string: String) -> Result<Vec<CommonScanRecord>, String> {
        let dropbox: DropBox = deserialize_dropbox(&db_string).await?;
        let mut return_vector: Vec<CommonScanRecord> = vec![];
        for mut address in dropbox.addresses {
            for i in 0..dropbox.global_ports.len() {
                address.ports.push(dropbox.global_ports[i]);
            }
            address.ports.dedup();

            match CommonScnr::host_ip_scan(&address.host, address.ports, 60).await {
                Ok(record) => return_vector.push(record),
                Err(error_message) => {
                    println!("{}", error_message)
                }
            }
        }
        Ok(return_vector)
    }
}

pub struct CommonScnr {}

impl CommonScnr {
    pub async fn host_ip_scan(
        host: &str,
        ports: Vec<u16>,
        timeout: u64,
    ) -> Result<CommonScanRecord, &str> {
        if let Ok(ip) = get_ip(host).await {
            let open_ports = IpScnr::scan_ip_addr(ip, ports, timeout)
                .await
                .expect("scan_ip_addr, hostscn error");
            let scan = ScanRecord {
                ip: ip.to_string(),
                open_ports,
            };
            let common_record = CommonScanRecord {
                host: String::from(host),
                scan,
            };
            Ok(common_record)
        } else {
            Err("host_scan error")
        }
    }

    pub async fn host_banner_scan(
        host: &str,
        ports: Vec<u16>,
        timeout: u64,
    ) -> Result<CommonBannerRecord, &str> {
        if let Ok(ip) = get_ip(host).await {
            let banner_records = IpScnr::banner_grab_ipaddr(ip, ports, timeout)
                .await
                .expect("scan_ip_addr, hostscn error");
            let host = host.to_string();
            let record = CommonBannerRecord {
                host,
                banner_scan: banner_records,
            };
            Ok(record)
        } else {
            Err("host_scan error")
        }
    }

    pub async fn hosts_banner_scan(
        hosts: Vec<&str>,
        ports: Vec<u16>,
        timeout: u64,
    ) -> Result<Vec<CommonBannerRecord>, &str> {
        let mut common_banner_vec: Vec<CommonBannerRecord> = vec![];
        for host in hosts {
            if let Ok(ip) = get_ip(host).await {
                let banner_records = IpScnr::banner_grab_ipaddr(ip, ports, timeout)
                    .await
                    .expect("scan_ip_addr, hostscn error");
                let host = host.to_string();
                let record = CommonBannerRecord {
                    host,
                    banner_scan: banner_records,
                };
                common_banner_vec.push(record)
            } else {
                continue;
            }
        }
        Ok(common_banner_vec)
    }

    pub async fn tcp_string_fuzz(
        host: &str,
        ports: Vec<u16>,
        timeout: u64,
        msg: String,
    ) -> Result<CommonBannerRecord, &str> {
        if let Ok(ip) = get_ip(host).await {
            let banner_records = IpScnr::fuzz_string_ipaddr(ip, ports, timeout, &msg)
                .await
                .expect("scan_ip_addr, hostscn error");
            let host = host.to_string();
            let record = CommonBannerRecord {
                host,
                banner_scan: banner_records,
            };
            Ok(record)
        } else {
            Err("host_scan error")
        }
    }

    pub async fn hosts_scan(
        hosts: Vec<&str>,
        ports: Vec<u16>,
        timeout: u64,
    ) -> Result<Vec<CommonScanRecord>, &str> {
        let mut scan_records: Vec<CommonScanRecord> = vec![];
        for host in hosts {
            if let Ok(ip) = get_ip(host).await {
                let open_ports = IpScnr::scan_ip_addr(ip, ports.clone(), timeout)
                    .await
                    .expect("scan");
                let host = host.to_string();
                let scan = ScanRecord {
                    ip: ip.to_string(),
                    open_ports,
                };
                let common_record = CommonScanRecord { host, scan };
                scan_records.push(common_record);
            }
        }
        Ok(scan_records)
    }

    pub async fn host_syn_scan_v4(
        host: &str,
        ports: Vec<u16>,
        timeout: u64,
    ) -> Result<CommonScanRecord, &str> {
        if let Ok(ip) = get_ip(host).await {
            if let Ok(open_ports) = syn_scan_v4(ports, ip) {
                let host = host.to_string();
                let scan = ScanRecord {
                    open_ports,
                    ip: ip.to_string(),
                };
                let common_record = CommonScanRecord { host, scan };
                return Ok(common_record);
            }
        }
        Err("missing")
    }

    pub async fn all_host_ip(
        host: &str,
        ports: Vec<u16>,
        timeout: u64,
    ) -> Result<Vec<CommonScanRecord>, &str> {
        let mut common_records: Vec<CommonScanRecord> = vec![];

        if let Ok(ips) = get_all_ips(host).await {
            for ip in ips {
                if let Ok(open_ports) = IpScnr::scan_ip_addr(ip, ports.clone(), timeout).await {
                    let host = host.to_string();
                    let scan_record = ScanRecord {
                        ip: ip.to_string(),
                        open_ports,
                    };
                    let record = CommonScanRecord {
                        host,
                        scan: scan_record,
                    };
                    common_records.push(record)
                }
            }
        } else {
            return Err("lookup host failed");
        }

        Ok(common_records)
    }
}

pub struct IpScnr {}

impl IpScnr {
    pub async fn scan_ip_addr(
        address: IpAddr,
        ports: Vec<u16>,
        timeout: u64,
    ) -> Result<Vec<u16>, std::io::Error> {
        let mut open_ports: Vec<u16> = vec![];
        for port in ports {
            let socket_address: SocketAddr = SocketAddr::new(address, port);
            match tokio::time::timeout(
                Duration::from_millis(timeout),
                TcpStream::connect(socket_address),
            )
            .await
            {
                Ok(stream_result) => {
                    if stream_result.is_ok() {
                        open_ports.push(port);
                    }
                }
                Err(_) => continue,
            }
        }
        Ok(open_ports)
    }

    pub async fn banner_grab_ipaddr(
        address: IpAddr,
        ports: Vec<u16>,
        timeout: u64,
    ) -> Result<Vec<BannerRecord>, std::io::Error> {
        let mut banner_records: Vec<BannerRecord> = vec![];
        for port in ports {
            let socket_address: SocketAddr = SocketAddr::new(address, port);

            match tokio::time::timeout(
                Duration::from_millis(timeout),
                TcpStream::connect(socket_address),
            )
            .await
            {
                Ok(stream_result) => {
                    if let Ok(mut stream) = stream_result {
                        let request = format!(
                            "\
                                                        HEAD / HTTP/1.1\r\n\
                                                        Host: {address}\r\n\
                                                        Connection: close\r\n\
                                                        \r\n\
                                                    "
                        );
                        stream.write_all(request.as_bytes()).await?;
                        let mut banner = String::new(); //Vec::new();
                        stream.read_to_string(&mut banner).await?;
                        let record = BannerRecord {
                            ip: address.to_string(),
                            port,
                            banner: parse_banner(&banner),
                        };
                        banner_records.push(record)
                    }
                }
                Err(_) => {
                    println!("timed out")
                }
            }
        }
        Ok(banner_records)
    }

    pub async fn fuzz_string_ipaddr(
        address: IpAddr,
        ports: Vec<u16>,
        timeout: u64,
        msg: &str,
    ) -> Result<Vec<BannerRecord>, std::io::Error> {
        let mut banner_records: Vec<BannerRecord> = vec![];
        for port in ports {
            let socket_address: SocketAddr = SocketAddr::new(address, port);

            match tokio::time::timeout(
                Duration::from_millis(timeout),
                TcpStream::connect(socket_address),
            )
            .await
            {
                Ok(stream_result) => {
                    if let Ok(mut stream) = stream_result {
                        let request = msg;
                        stream.write_all(request.as_bytes()).await?;
                        let mut banner = String::new(); //Vec::new();
                        stream.read_to_string(&mut banner).await?;
                        let record = BannerRecord {
                            ip: address.to_string(),
                            port,
                            banner: parse_banner(&banner),
                        };
                        banner_records.push(record)
                    }
                }
                Err(_) => {
                    println!("timed out")
                }
            }
        }
        Ok(banner_records)
    }
}

fn parse_banner(banner: &str) -> String {
    let b_vec = Vec::from_iter(banner.split(' '));
    String::from(b_vec[0])
}

/// Creates tcp packet with the SYN flag and given options
fn create_tcp_packet(
    buff: &mut [u8],
    source_port: u16,
    destination_port: u16,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> MutableTcpPacket {
    let mut packet = MutableTcpPacket::new(buff).unwrap();
    packet.set_flags(pnet::packet::tcp::TcpFlags::SYN);
    packet.set_source(source_port);
    packet.set_destination(destination_port);
    packet.set_window(1024);
    packet.set_data_offset(6);
    packet.set_sequence(rand::random::<u32>());
    packet.set_options(&[pnet::packet::tcp::TcpOption::mss(1460)]);
    packet.set_checksum(pnet::packet::tcp::ipv4_checksum(
        &packet.to_immutable(),
        &source_ip,
        &target_ip,
    ));
    packet
}

/// Sends packets to the given address from the given port
fn syn_scan_v4(ports: Vec<u16>, target_ip: IpAddr) -> Result<Vec<u16>, std::io::Error> {
    let open_ports: Vec<u16> = Vec::new();
    let channel_type = pnet_transport::TransportChannelType::Layer4(
        pnet_transport::TransportProtocol::Ipv4(pnet::packet::ip::IpNextHeaderProtocols::Tcp),
    );
    let (mut tx, _) = match pnet_transport::transport_channel(4096, channel_type) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e),
    };
    let interfaces = pnet_datalink::interfaces();
    let iface = interfaces
        .into_iter()
        .find(|iface| iface.name == "en0")
        .unwrap();

    let (_, mut receiver) = match pnet_datalink::channel(&iface, Default::default()) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Wrong channel type"),
        Err(e) => panic!("Error while creating a channel on given interface: {}", e),
    };

    let source_port: u16 = 0;
    let source_ip = iface.ips[0].ip();
    let target_ip = target_ip;
    let mut buff: [u8; 24] = [0; 24];
    let target = Ipv4Addr::from_str(&target_ip.to_string()).unwrap();

    for port in ports {
        let packet = create_tcp_packet(
            &mut buff,
            source_port,
            port,
            Ipv4Addr::from_str(&source_ip.to_string()).unwrap(),
            target,
        );
        match tx.send_to(packet, IpAddr::V4(target)) {
            Ok(_) => {
                if let Ok(buff) = receiver.next() {
                    let ethernet = pnet::packet::ethernet::EthernetPacket::new(&buff).unwrap();
                    let ipv4 = pnet::packet::ipv4::Ipv4Packet::new(ethernet.payload()).unwrap();
                    if ipv4.get_next_level_protocol()
                        == pnet::packet::ip::IpNextHeaderProtocols::Tcp
                    {
                        let tcp = pnet::packet::tcp::TcpPacket::new(ipv4.payload()).unwrap();
                        if tcp.get_flags()
                            == pnet::packet::tcp::TcpFlags::SYN + pnet::packet::tcp::TcpFlags::ACK
                        {
                            open_ports.push(tcp.get_source())
                        }
                    }
                }
            }
            Err(e) => return Err(e),
        };
    }

    Ok(open_ports)
}

async fn deserialize_dropbox(data: &str) -> Result<DropBox, String> {
    // Parse the string of data into serde_json::Value.
    let drop_box: DropBox = serde_json::from_str(data).expect("could not serialize");

    Ok(drop_box)
}
