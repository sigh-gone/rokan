


pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use crate::dns_records;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
             };
        }



    #[test]
    fn it_works() {
        let dns = aw!(dns_records());
        println!("{:?}", dns);
        assert_eq!(true,false)
    }
}

pub struct DomainRecord<A,B,C,D>{
    a_records:Vec<A>,
    aaaa_records:Vec<B>,
    mx_records:Vec<C>,
    soa_records:Vec<D>,
}


    use rustdns::Message;
    use rustdns::types::*;
    use std::net::UdpSocket;
    use std::time::Duration;
    use google_dns_rs::api::{Dns, DoH, Result};
    async fn dns_records(){
 
    
    }

