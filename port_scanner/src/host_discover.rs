use std::{net::{IpAddr, AddrParseError}, str::FromStr};

use dns_lookup::lookup_host;

pub async fn get_ip(addr: &str) -> std::result::Result<IpAddr, AddrParseError> {
    match IpAddr::from_str(addr) {
        Err(_) => {
            let ip_vecs: Vec<IpAddr> = lookup_host(addr).unwrap();
            IpAddr::from_str(&ip_vecs[0].to_string())
        }

        Ok(IpAddr::V4(..)) => IpAddr::from_str(addr),
        Ok(IpAddr::V6(..)) => IpAddr::from_str(addr),
    }
}

pub async fn get_all_ips(addr: &str) -> std::result::Result<Vec<IpAddr>, &str> {
            if let Ok(ip_vector)= lookup_host(addr){
                Ok(ip_vector)
            }else{
                Err("get_all_ips error")
            }
    }

