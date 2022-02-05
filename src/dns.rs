use deku::prelude::*;

use std::collections::HashMap;
use std::backtrace::Backtrace;

struct PacketParser<'a> {
    /// A buffer that *should* contain a DNS packet.
    buffer: &'a [u8; 512],
    /// A pointer to an unparsed packet position.
    current: usize,
    /// Holds offsets that map to decompressed names.
    decompress_map: HashMap<u8, Vec<u8>>,
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
    fn new(header: Header, 
        questions: Vec<Question>, 
        answers: Vec<Record>, 
        authorities: Vec<Record>, 
        additionals: Vec<Record>
    ) -> Self { 
        Self { header, questions, answers, authorities, additionals } 
    }
}

#[derive(Debug, Default, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
struct Header {
    // packet identifier
    id: u16,
        // flags
        #[deku(bits = "1")]
        // query response
        qr: u8, 
        #[deku(bits = "4")]
        // operation code
        opcode: u8, 
        #[deku(bits = "1")]
        // authoritive answer
        aa: u8, 
        #[deku(bits = "1")]
        // truncated message
        tc: u8, 
        #[deku(bits = "1")]
        // recursion desired
        rd: u8, 
        #[deku(bits = "1")]
        // recursion available
        ra: u8, 
        #[deku(bits = "3")]
        // reserved (edns)
        z: u8, 
        #[deku(bits = "4")]
        // response code
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
#[deku(endian = "big")]
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
#[deku(endian = "big")]
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
        Self { buffer, current: 0, decompress_map: HashMap::new() }
    } 
 
    /// Returns byte at current pointer position.
    fn get_current_byte(&self) -> u8 {
        self.buffer[self.current]
    }

    /// Returns whether or not current byte is a compressed name jump opcode.
    fn is_current_jmp(&mut self) -> bool {
       self.get_current_byte() & 0xC0 == 0xC0 
    }

    /// Shows byte one byte ahead without consuming it.
    fn peek(&self) -> Option<u8> {
        self.buffer.get(self.current + 1).copied() 
    }

    /// Count the number of bytes until peeked byte = 0.
    fn get_name_length(&self) -> usize {
        self.buffer
            .iter()
            .skip(self.current)
            .take_while(|&&b| b != 0)
            .count() + 1
    }

    /// Gets range of bytes starting from `current` to `n`.
    ///
    /// Makes sure it doesn't overstep its bounds out of the buffer.
    fn advance_n(&mut self, n: usize) -> Result<&[u8], String> {
        match self.buffer.get(self.current + n).copied() {
            None => Err(format!("couldn't advance far enough. [{}/{}]\n\n{}", 
                    self.current + n + 1, self.buffer.len(), 
                    Backtrace::force_capture())),
            Some(_) => { 
                self.current += n; 
                Ok(&self.buffer[self.current - n..self.current]) 
            },
        } 
    }
    
    /// Parses variable length name field from bytes.
    ///
    /// Increments position pointer by name length and returns vector of name bytes.
    fn parse_name(&mut self) -> Result<Vec<u8>, String> {
        if self.is_current_jmp() { 
            /*
            let name = self.decompress_map
                           .get(&mut self.peek().unwrap())
                           .unwrap();
            */
            return Ok(self.advance_n(2)?.to_vec());
        } 

        let name: Vec<u8> = self.advance_n(self.get_name_length())?.to_vec();
        
        // NOTE: currently inserts current after its be modified, need to log before or subtract
        // by name length, also do something about the clone there, later. 
        self.decompress_map.insert(self.current as u8, name.clone());
        
        Ok(name)
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
        
        /* Parse Answer Section */
        let mut answers: Vec<Record> = Vec::with_capacity(header.an_count as usize);

        for _ in 0..answers.capacity() {
            let mut answers_bytes = self.parse_name()?;

            answers_bytes.extend_from_slice(self.advance_n(8)?);

            let length = u16::from_be_bytes(self.advance_n(2)?.try_into().unwrap());

            let data = self.advance_n(length as usize)?;

            answers_bytes.append(&mut [&length.to_be_bytes()[..], data].concat());

            answers.push(Record::try_from(answers_bytes.as_ref()).unwrap());
        }

        /* Parse Authority Section */
        let mut authorities: Vec<Record> = Vec::with_capacity(header.ns_count as usize);

        /* Parse Additional Section */
        let mut additionals: Vec<Record> = Vec::with_capacity(header.ar_count as usize);
        
        Ok(DNSPacket::new(header, questions, answers, authorities, additionals))
    }
}

pub fn test() {
    let mut buf: [u8; 512] = [0; 512]; 
    buf[..69].copy_from_slice(include_bytes!("response_packet.txt"));
    let x = PacketParser::new(&buf).deserialize();
    match x {
        Ok(p) => println!("{:#X?}", p),
        Err(e) => println!("\nError: {}", e)
    }
}
