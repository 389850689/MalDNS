#![feature(backtrace)]
mod dns;

use dns::*;
use std::net::UdpSocket;
use std::time::SystemTime;
use std::backtrace::Backtrace;

fn main() {
    // NOTE: at some point might be nice to support edns and communicate over TCP.
    let socket = UdpSocket::bind("10.0.0.249:53").unwrap();

    // receive buffer used for all communication.
    let mut buffer: [u8; 512] = [0; 512];

    loop {
        // if receive fails retries.
        let (_, src) = match socket.recv_from(&mut buffer) {
            Ok((l, s)) => (l, s),  
            Err(_) => continue,
        };
        
        // parse query packet, if fails, starts listening for another packet.
        let query = match PacketParser::new(&buffer).deserialize() {
            Ok(p) => p,
            Err(e) => { eprintln!("Error: {}", e); continue }
        };

        // send query packet to google's DNS server.
        if let Err(e) = socket.send_to(&buffer, "8.8.8.8:53") {
            eprintln!("Error: {:?}\n\n{}", e, Backtrace::force_capture());
            continue;
        }
        
        // used to keep track if the response packet is.. the response packet.
        let query_id = query.header.id;

        // get current time to use for timeout.
        let current_time = SystemTime::now();

        // TODO: use an actual agreed upon timeout time.
        // returns Option<DNSPacket>, loops until it receives response packet or timeout.
        let response = loop {
            let (_, _) = match socket.recv_from(&mut buffer) {
                Ok((l, s)) => (l, s),  
                Err(_) => continue,
            };

            let response = match PacketParser::new(&buffer).deserialize() {
                Ok(p) => p,
                Err(e) => { eprintln!("Error: {}", e); break None; }
            };
            
            // TODO: also check if the response addr is from the right ip.
            // break from the loop if the response is the correct DNS packet.
            if response.header.id == query_id {
                break Some(response);
            }

            // set timeout to 5 seconds.
            if current_time.elapsed().unwrap().as_secs() >= 5 {
                break None;
            }
        };

        // if we didn't timeout, and the `DNSPacket` parsed without error.
        if let Some(mut response) = response {
            // the following performs a sneaky. 
            if response.questions[0].get_name_as_string().contains("google.com") {
                 response.answers
                         .iter_mut()
                         .for_each(|r| r.data = u32::to_be_bytes(0x01_03_03_07).into());
            }

            // sends response packet back to client.
            socket.send_to(response.serialize().as_ref(), src).unwrap();
        }
    }
}
