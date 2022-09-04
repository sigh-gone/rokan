use rustdns::types::*;
use rustdns::Message;
use rustdns::Resource::*;
use std::io::Error;
use std::net::UdpSocket;
use std::time::Duration;

#[derive(Debug)]
pub struct DomainRecord {
    a_records: Vec<String>,
    aaaa_records: Vec<String>,
    mx_records: Vec<String>,
    soa_records: Vec<String>,
    txt_records: Vec<String>,
    ns_records: Vec<String>,
    cname_records: Vec<String>,
    srv_records:Vec<String>,
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
        a_records:vec![],
        aaaa_records:vec![],
        mx_records:vec![],
        soa_records:vec![],
        txt_records:vec![],
        ns_records:vec![],
        cname_records:vec![],
        srv_records:vec![],
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
                    dns_record.a_records.push(resp.to_string());
                },
                AAAA(resp) => {
                    dns_record.aaaa_records.push(resp.to_string());
                },
                CNAME(resp) => {
                    dns_record.cname_records.push(resp);
                },
                NS(resp) => {
                    dns_record.ns_records.push(resp);
                },
                PTR(_) => {},
                TXT(resp) => {
                    dns_record.txt_records.push(resp.to_string());
                },
                SPF(_) => {},
                MX(resp) => {
                    dns_record.mx_records.push(resp.to_string());
                },
                SOA(resp) => {
                    dns_record.soa_records.push(resp.to_string());
                },
                SRV(resp) =>{
                    dns_record.srv_records.push(resp.to_string());
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
        assert!(!dns.unwrap().a_records.is_empty());
    }
}