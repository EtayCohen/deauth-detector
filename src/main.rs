use pcap::{Capture, Device};

fn main() {
    let mut cap = pcap::Capture::from_device("en1")
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .rfmon(true)
        .open()
        .unwrap();

    while let Ok(packet) = cap.next() {
        println!("received packet! {:?}", packet);
    }
}
