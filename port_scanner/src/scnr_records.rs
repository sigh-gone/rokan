use serde::{Deserialize, Serialize};
/**
Props:

Ip -> host ip of the port scan.

open_ports -> the ports that are open in the host.
*/
#[derive(Debug)]
pub struct ScanRecord {
    pub ip: String,
    pub open_ports: Vec<u16>,
}

/**
Props:

host -> host of the port scan.

scan -> contains the ScanRecord.
 */
#[derive(Debug)]
pub struct CommonScanRecord {
    pub host: String,
    pub scan: ScanRecord,
}

/**
Props:

host -> host of the banner scan.

banner_scan -> the banner of the port.
 */
#[derive(Debug)]
pub struct CommonBannerRecord {
    pub host: String,
    pub banner_scan: Vec<BannerRecord>,
}

/**
Props:

host--> host where the banner was grabbed

port--> port where banner was grabbed

banner--> the banner in string format ready to be parsed.
*/
#[derive(Debug)]
pub struct BannerRecord {
    pub ip: String,
    pub port: u16,
    pub banner: String,
}

/**
Props:

port--> port where banner was grabbed

banner--> the banner in string format ready to be parsed.

service--> service of parsed banner
 */
#[derive(Serialize, Deserialize, Debug)]
pub struct Address {
    pub host: String,
    pub ports: Vec<u16>,
}

/**
Props:

port--> port where banner was grabbed

banner--> the banner in string format ready to be parsed.

service--> service of parsed banner
 */

#[derive(Debug, Deserialize, Serialize)]
pub struct DropBox {
    pub addresses: Vec<Address>,
    pub global_ports: Vec<u16>,
}
