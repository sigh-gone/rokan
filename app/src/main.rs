fn main() {
    let _ = udp_example();
}
use rustdns::Message;
use rustdns::types;
use rustdns::types::*;
use std::net::UdpSocket;
use std::time::Duration;
use rustdns::Resource::*;

fn udp_example() -> std::io::Result<()> {

    // Setup a UDP socket for sending to a DNS server.
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::new(5, 0)))?;
    socket.connect("8.8.8.8:53")?;

    // A DNS Message can be easily constructed
    let mut m = Message::default();
    m.add_extension(Extension {   // Optionally add a EDNS extension
        payload_size: 4096,       // which supports a larger payload size.
        ..Default::default()
    });
    m.add_question("bramp.net", Type::TXT, Class::Internet);

    // Encode the DNS Message as a Vec<u8>.
    let question = m.to_vec()?;

    // Send to the server.
    socket.send(&question)?;

    // Wait for a response from the DNS server.
    let mut resp = [0; 4096];
    let len = socket.recv(&mut resp)?;

    // Take the response bytes and turn it into another DNS Message.
    let answer = Message::from_slice(&resp[0..len])?;

    // Now do something with `answer`, in this case print it!
    println!("DNS Response:\n{}", answer);

    let mut m = Message::default();
    m.add_question("bramp.net", Type::A, Class::Internet);

    // Encode the DNS Message as a Vec<u8>.
    let question = m.to_vec()?;

    // Send to the server.
    socket.send(&question)?;

    // Wait for a response from the DNS server.
    let mut resp = [0; 4096];
    let len = socket.recv(&mut resp)?;

    // Take the response bytes and turn it into another DNS Message.
    let answer = Message::from_slice(&resp[0..len])?;

    // Now do something with `answer`, in this case print it!
    for answerr in answer.answers.into_iter() {
        println!("{:?}",answerr.resource);
        match answerr.resource {
            A(_) => todo!(),
            AAAA(_) => todo!(),
            CNAME(_) => todo!(),
            NS(_) => todo!(),
            PTR(_) => todo!(),
            TXT(_) => todo!(),
            SPF(_) => todo!(),
            MX(_) => todo!(),
            SOA(_) => todo!(),
            SRV(_) => todo!(),
            OPT => todo!(),
            ANY => todo!(),
        }
    }

    Ok(())
}