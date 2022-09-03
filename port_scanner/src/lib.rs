pub mod host_discover;
pub mod port_scanner;
pub mod scnr_records;



#[cfg(test)]
mod ip_scnr_tests {
    use std::{net::IpAddr, str::FromStr};
    use crate::port_scanner::IpScnr;
    macro_rules! aw {
    ($e:expr) => {
        tokio_test::block_on($e)
         };
    }

    #[test]
    fn scan_ip_addr_test() {
        let ip = IpAddr::from_str("142.251.215.238").expect("ip parse failed");
        let ports:Vec<u16>= vec![443];
        let record = aw!(IpScnr::scan_ip_addr(ip,ports,100));
        assert!(record.is_ok());
        let unwrapped = record.unwrap();
        assert_eq!(unwrapped.len(), 1);
    }
}

#[cfg(test)]
mod common_scnr_tests {
    use crate::port_scanner::CommonScnr;

    macro_rules! aw {
    ($e:expr) => {
        tokio_test::block_on($e)
         };
    }

    #[test]
    fn common_scnr_single_host_test(){
        let record = aw!(CommonScnr::host_ip_scan("youtube.com", vec![443], 100));
        assert!(record.is_ok());
        let record = record.unwrap();
        assert!(!record.scan.open_ports.is_empty());
    }
    #[test]
    fn common_scnr_all_host_test(){
        let record = aw!(CommonScnr::hosts_scan(vec!["youtube.com"], vec![443], 100));
        assert!(record.is_ok());
        let records = record.unwrap();
        assert!(!records.is_empty());
        assert!(!records[0].scan.open_ports.is_empty());
    }
    #[test]
    fn common_all_host_ip_test(){
        let record = aw!(CommonScnr::all_host_ip("youtube.com", vec![443], 100));
        assert!(record.is_ok());
        let records = record.unwrap();
        assert!(!records.is_empty());
        assert!(!records[0].scan.open_ports.is_empty());
    }

}
#[cfg(test)]
mod dropbox_scnr_tests {
    use crate::port_scanner::DropBoxScnr;

    macro_rules! aw {
    ($e:expr) => {
        tokio_test::block_on($e)
         };
    }

    #[test]
    fn dropbox_from_file_test(){
        let record = aw!(DropBoxScnr::from_file("../assets/dropbox.json"));
        assert!(record.is_ok());
        let records = record.unwrap();
        assert!(!records.is_empty());
    }

}

