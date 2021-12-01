use chrono::Utc;
use pcap;
use std::env;
use std::time::SystemTime;

fn main() {
    const DEFAULT_THRESHOLD: u32 = 150;
    const SUBTYPE_DEAUTH: u8 = 0xC0;
    const SUBTYPE_DISASS: u8 = 0xA0;
    let mut packets_count: u32 = 0;
    let mut attack_ongoing: bool = false;
    let mut current_time = SystemTime::now();

    let args: Vec<String> = env::args().collect();

    if args.len() >= 2 {
        let threshold: u32 = if args.len() == 3 {
            args[2].parse().unwrap()
        } else {
            DEFAULT_THRESHOLD
        };
        let interface: &str = &args[1].to_string();

        let mut cap = pcap::Capture::from_device(interface)
            .unwrap()
            .promisc(true)
            .immediate_mode(true)
            .rfmon(true)
            .open()
            .unwrap();

        while let Ok(packet) = cap.next() {
            if packet.len() < 28
                || !(packet.data[25] == SUBTYPE_DEAUTH || packet.data[25] == SUBTYPE_DISASS)
            {
                continue;
            }
            packets_count += 1;
            if current_time.elapsed().unwrap().as_secs() >= 1 {
                if packets_count > threshold {
                    if !attack_ongoing {
                        println!("An deauth attack was detected!");
                    }
                    attack_ongoing = true;
                    println!(
                        "{:?} Deauth / Disass Packets rate is: {} a second",
                        Utc::now(),
                        packets_count
                    );
                }
                packets_count = 0;
                current_time = SystemTime::now();
            }
        }
    }
}
