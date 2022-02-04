use deku::prelude::*;
use std::backtrace::Backtrace;

struct PacketParser<'a> {
    /// A buffer that *should* contain a DNS packet.
    buffer: &'a [u8; 512],
    /// A pointer to an unparsed packet position.
    current: usize,
}

#[derive(Debug, Default)]
struct DNSPacket {
    header: Header,
    questions: Vec<Question>, 
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
}

impl DNSPacket {
    fn new() -> Self { Self { ..Default::default() } }
}

#[derive(Debug, Default, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
struct Header {
    // packet identifier
    id: u16,
        // flags
        #[deku(bits = "1")]
        qr: u8, 
        #[deku(bits = "4")]
        opcode: u8, 
        #[deku(bits = "1")]
        aa: u8, 
        #[deku(bits = "1")]
        tc: u8, 
        #[deku(bits = "1")]
        rd: u8, 
        #[deku(bits = "1")]
        ra: u8, 
        #[deku(bits = "3")]
        z: u8, 
        #[deku(bits = "4")]
        r_code: u8,
    // question count
    qd_count: u16,
    // answer count
    an_count: u16,
    // authority count
    ns_count: u16,
    // additional coount
    ar_count: u16
}

#[derive(Debug, Default, PartialEq, DekuRead, DekuWrite)]
struct Question {
    // domain name
    #[deku(until = "|v: &u8| *v == 0")] 
    name: Vec<u8>,
    // type of query
    ty: u16,
    // class of query 
    class: u16,
}

#[derive(Debug, Default, PartialEq, DekuRead, DekuWrite)]
struct Record {
    // domain name
    // TODO: change this to a Vec<u8> again after testing.
    name: u16,  
    // name of record
    ty: u16,
    // type of record
    class: u16,
    // time to live before cache expires
    ttl: u32,
    // length of data 
    len: u16,
    // the data for an A record
    #[deku(count = "len", endian = "big")]
    data: Vec<u8>
}

impl<'a> PacketParser<'a> {
    fn new(buffer: &'a [u8; 512])-> Self {
        Self { buffer, current: 0 }
    } 

    /// Returns byte at current pointer position.
    fn get_current_byte(&self) -> u8 {
        self.buffer[self.current]
    }

    /// Returns if current pointer position is at the end of the buffer.
    fn at_end(&self) -> bool {
        self.current >= self.buffer.len()
    }

    /// Jumps to a position in the buffer (an offset).
    /// 
    /// Sets the current pointer to `position` and returns the byte at that position.
    fn jmp(&mut self, position: usize) -> Option<u8> {
        match self.buffer.get(position).copied() {
            None => None,
            Some(byte) => { self.current = position; Some(byte) }
        }
    }

    /// Gets next byte from buffer.
    ///
    /// Makes sure it doesn't overstep its bounds out of the buffer, returns `None` at the EOF.
    fn advance(&mut self) -> Option<u8> {
        // TODO: find an actual solution to this.
        if self.current == 0 { self.current += 1; return Some(self.buffer[0]); }

        match self.buffer.get(self.current + 1).copied() {
            None => None,
            // TODO: find a more concise way to increment the current pointer.
            Some(byte) => { self.current += 1; Some(byte) },
        } 
    }

    /// It's like advance but with n steps, and returns a slice of bytes.
    fn advance_n(&mut self, n: usize) -> Result<&[u8], String> {
        match self.buffer.get(self.current + n).copied() {
            None => Err(format!("couldn't advance far enough. [{}/{}]\n\n{}", 
                    self.current + n, self.buffer.len(), 
                    Backtrace::force_capture())),
            Some(_) => { 
                self.current += n; 
                Ok(&self.buffer[self.current - n..self.current]) 
            },
        } 
    }

    fn parse_name(&self) -> Result<Vec<u8>, &str> {
        if 1 == 1 {} 
        Ok(vec![0])
    }

    /// Parses packet bytes and turns them in a `DNSPacket`. 
    fn deserialize(&mut self) -> Result<DNSPacket, String> {
        /* Parse Header */
        let header_bytes = self.advance_n(12)?;

        let (_, header) = Header::from_bytes((header_bytes.as_ref(), 0)).unwrap();

        /* Parse Question Section */
        let mut questions: Vec<Question> = Vec::with_capacity(header.qd_count as usize);

        for _ in 0..questions.capacity() {
            let mut question_bytes = self.parse_name()?;

            // concatenates the next 4 bytes after the name field onto the name bytes.
            question_bytes.extend_from_slice(self.advance_n(4)?);

            questions.push(Question::try_from(question_bytes.as_ref()).unwrap());
        }

        Err(String::new())
    }
}

pub fn test() {
    let mut buf: [u8; 512] = [0; 512]; 
    buf[..69].copy_from_slice(include_bytes!("response_packet.txt"));
    let x = PacketParser::new(&buf).deserialize();
    match x {
        Ok(p) => println!("{:#?}", p),
        Err(e) => println!("Error: {}", e)
    }
}
