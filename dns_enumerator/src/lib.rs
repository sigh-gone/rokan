use rustdns::types::*;
use rustdns::Message;
use rustdns::Resource::*;
use std::io::Error;
use std::net::UdpSocket;
use std::time::Duration;

#[derive(Debug)]
pub struct DomainRecord {
    a: Vec<String>,
    aaaa: Vec<String>,
    mx: Vec<String>,
    soa: Vec<String>,
    txt: Vec<String>,
    ns: Vec<String>,
    cname: Vec<String>,
    srv:Vec<String>,
}
#[derive(Debug)]
pub struct HostDnsRecord {
    host:String,
    domain_record:DomainRecord
}



pub fn host_dns(host:&str)->Result<HostDnsRecord, &str>{

        if let Ok(dns_records) = dns_records(host){
            let host_dns_record = HostDnsRecord{ host : String::from(host), domain_record: dns_records};
            Ok(host_dns_record)
        }else{
            Err("host_dns failed")
        }

}

pub fn multi_host_dns(hosts:Vec<&str>)->Result<Vec<HostDnsRecord>, Box<Error>>{
    let mut ret_vec :Vec<HostDnsRecord> = vec![];

    for host in hosts {
        if let Ok(dns_records) = dns_records(host){
            let host_dns_record = HostDnsRecord{ host : String::from(host), domain_record: dns_records};
            ret_vec.push(host_dns_record);
        }
    }
    Ok(ret_vec)
}

pub fn dns_records(host: &str) -> Result<DomainRecord, Box<Error>> {
    // Setup a UDP socket for sending to a DNS server.
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::new(5, 0)))?;
    socket.connect("8.8.8.8:53")?;
    let rtype_vec = [
        Type::A,
        Type::AAAA,
        Type::MX,
        Type::SOA,
        Type::TXT,
        Type::NS,
        Type::CNAME,
        Type::SRV,
    ];
    let mut dns_record = DomainRecord{
        a:vec![],
        aaaa:vec![],
        mx:vec![],
        soa:vec![],
        txt:vec![],
        ns:vec![],
        cname:vec![],
        srv:vec![],
    };

    for rtype in rtype_vec {
        // A DNS Message can be easily constructed
        let mut m = Message::default();
        m.add_extension(Extension {
            // Optionally add a EDNS extension
            payload_size: 4096, // which supports a larger payload size.
            ..Default::default()
        });
        m.add_question(host, rtype, Class::Internet);

        // Encode the DNS Message as a Vec<u8>.
        let question = m.to_vec()?;

        // Send to the server.
        socket.send(&question)?;

        // Wait for a response from the DNS server.
        let mut resp = [0; 4096];
        let len = socket.recv(&mut resp)?;

        // Take the response bytes and turn it into another DNS Message.
        let answer = Message::from_slice(&resp[0..len])?;

        for record in answer.answers.into_iter() {
            match record.resource {
                A(resp) => {
                    dns_record.a.push(resp.to_string());
                },
                AAAA(resp) => {
                    dns_record.aaaa.push(resp.to_string());
                },
                CNAME(resp) => {
                    dns_record.cname.push(resp);
                },
                NS(resp) => {
                    dns_record.ns.push(resp);
                },
                PTR(_) => {},
                TXT(resp) => {
                    dns_record.txt.push(resp.to_string());
                },
                SPF(_) => {},
                MX(resp) => {
                    dns_record.mx.push(resp.to_string());
                },
                SOA(resp) => {
                    dns_record.soa.push(resp.to_string());
                },
                SRV(resp) =>{
                    dns_record.srv.push(resp.to_string());
                },
                OPT => {},
                ANY => {},
            }
        }
    }

    Ok(dns_record)
}

#[cfg(test)]
mod dns_tests {
    use crate::dns_records;


    #[test]
    fn dns_test() {
        let dns =dns_records("example.com");
        println!("{:?}", dns);
        assert!(dns.is_ok());
        assert!(!dns.unwrap().a.is_empty());
    }
}