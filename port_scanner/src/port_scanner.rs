
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncReadExt};
use tokio::net::TcpStream;
use crate::host_discover::{get_ip, get_all_ips};
use crate::scnr_records::{ScanRecord, DropBox, CommonScanRecord};


pub struct DropBoxScnr{}

impl DropBoxScnr{
    pub async fn from_file(file_name: &str) -> Result<Vec<CommonScanRecord>, &str> {
        let mut file = File::open(file_name).await.expect("could not open file");
        let mut data = String::new();

        file.read_to_string(&mut data).await.expect("could not open read to string");

        let records = DropBoxScnr::from_string(data).await.expect("dropboxscnr failure");

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
                Ok(record)=>{return_vector.push(record)},
                Err(error_message)=>{println!("{}",error_message)}
            }
        }
        Ok(return_vector)
    }
}


pub struct CommonScnr {}

impl CommonScnr{
    pub async fn host_ip_scan(
        host:&str,
        ports: Vec<u16>,
        timeout: u64)-> Result<CommonScanRecord, &str>{
        if let Ok(ip) = get_ip(host).await{
            let open_ports = IpScnr::scan_ip_addr(ip, ports, timeout)
            .await
            .expect("scan_ip_addr, hostscn error");
            let scan = ScanRecord {ip: ip.to_string(), open_ports };
            let common_record = CommonScanRecord{ host: String::from(host), scan };
            Ok(common_record)
        }else{
            Err("host_scan error")
        }

    }
    
    /*pub async fn host_banner_scan(
        host:&str,
        ports: Vec<u16>,
        timeout: u64)-> Result<CommonBannerRecord, &str>{
        if let Ok(ip) = get_ip(host).await{
            let banner_records = IpScnr::banner_grab_ipaddr(ip, ports, timeout)
            .await
            .expect("scan_ip_addr, hostscn error");
            let host = host.to_string();
            let record = CommonBannerRecord { host, banner_scan: banner_records };
            Ok(record)
        }else{
            Err("host_scan error")
        }

    }*/

    pub async fn hosts_scan(
        hosts:Vec<&str>,
        ports: Vec<u16>,
        timeout: u64)-> Result<Vec<CommonScanRecord>, &str>{
            let mut scan_records :Vec<CommonScanRecord>=vec![];
            for host in hosts{
                if let Ok(ip) = get_ip(host).await{
                    let open_ports = IpScnr::scan_ip_addr(ip, ports.clone(), timeout).await.expect("scan");
                    let host = host.to_string();
                    let scan = ScanRecord {ip:ip.to_string(), open_ports };
                    let common_record = CommonScanRecord {host, scan};
                    scan_records.push(common_record);
                }
            }
            Ok(scan_records)

    }

    pub async fn all_host_ip(
        host:&str,
        ports: Vec<u16>,
        timeout: u64)-> Result<Vec<CommonScanRecord>, &str>{
            let mut common_records:Vec<CommonScanRecord>=vec![];

            if let Ok(ips) = get_all_ips(host).await{
                for ip in ips {
                    if let Ok(open_ports) = IpScnr::scan_ip_addr(ip, ports.clone(), timeout).await {
                        let host = host.to_string();
                        let scan_record = ScanRecord { ip: ip.to_string(), open_ports };
                        let record = CommonScanRecord { host, scan: scan_record };
                        common_records.push(record)
                    }
                }
            }else{
                return Err("lookup host failed")
            }

            Ok(common_records)

    }

}






pub struct IpScnr {}

impl IpScnr {

    pub async fn scan_ip_addr(address: IpAddr,
        ports: Vec<u16>,
        timeout: u64,
    ) -> Result<Vec<u16>, std::io::Error> {
        let mut open_ports: Vec<u16>= vec![];
        for port in ports {
            let socket_address: SocketAddr = SocketAddr::new(address, port);
            match tokio::time::timeout(
                Duration::from_millis(timeout),
                  TcpStream::connect(socket_address)).await{
                Ok(stream_result)=>{
                    if stream_result.is_ok() {
                        open_ports.push(port);
                    }
                },
                Err(_)=>{continue},
            }
        }
        Ok(open_ports)
    }

    /*
    banner grabber in the works

    pub async fn banner_grab_ipaddr(address: IpAddr,
                                    ports: Vec<u16>,
                                    timeout: u64,
    ) -> Result<Vec<BannerRecord>, std::io::Error> {
        let mut banner_records: Vec<BannerRecord>= vec![];
        for port in ports {
            let socket_address: SocketAddr = SocketAddr::new(address, port);

            match tokio::time::timeout(Duration::from_millis(timeout), TcpStream::connect(socket_address)).await {
                Ok(stream_result)=>{
                    if let Ok(mut stream) = stream_result {
                        let mut banner = String::new();
                        //stream.read_to_string(&mut banner).await?;
                        if banner.is_empty() {
                            let request = format!("HEAD / HTTP/1.1\r\n");
                            stream.write_all(request.as_bytes()).await?;
                            let mut banner = Vec::new();
                            stream.read_to_end(&mut banner).await?;
                        }
                        //let banner_string = String::from_utf8(banner).unwrap();
                        let record = BannerRecord { ip:address.to_string(), port, banner:parse_banner(&banner) };
                        banner_records.push(record)

                        /*let (mut read, mut write) = tokio::io::split(stream);
                        let query =  "GET / HTTP/1.1\n\n".as_bytes();
                        let mut buf = String::new();
                        read.read_to_string(&mut buf).await.unwrap();

                        if buf.is_empty() {
                            let _ = write.write_all(query);
                            read.read_to_string(&mut buf).await.unwrap();
                        }

                        let record = BannerRecord { ip:address.to_string(), port, banner:parse_banner(&buf) };
                        banner_records.push(record)*/
                    }
                },
                Err(_)=>{println!("timed out")},
            }
        }
        Ok(banner_records)
    }*/


}
/*
fn parse_banner(banner: &str) -> String {
    let b_vec = Vec::from_iter(banner.split(' '));
    String::from(b_vec[0])
    
}*/

async fn deserialize_dropbox(data: &str) -> Result<DropBox, String> {
    // Parse the string of data into serde_json::Value.
    let drop_box: DropBox = serde_json::from_str(data).expect("could not serialize");

    Ok(drop_box)
}