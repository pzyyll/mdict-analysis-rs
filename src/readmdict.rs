#![allow(unused)]

use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{BufReader, Cursor, Read, Seek, SeekFrom, Write},
    iter, result,
};

use adler2::adler32_slice;
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use encoding_rs::{Encoding, UTF_16LE, UTF_8};
use flate2::read::ZlibDecoder;
use regex::{bytes::Regex as BytesRegex, Regex};
use rust_lzo::LZOContext;
use xxhash_rust::xxh64::xxh64;

use crate::pure_salsa20::Salsa20;
use crate::ripemd128::ripemd128;

enum NumberFormat {
    BI,
    BQ,
    BH,
    BB,
}

impl NumberFormat {
    fn as_str(&self) -> &str {
        match self {
            NumberFormat::BI => ">I",
            NumberFormat::BQ => ">Q",
            NumberFormat::BH => ">H",
            NumberFormat::BB => ">B",
        }
    }

    fn size(&self) -> usize {
        match self {
            NumberFormat::BI => 4,
            NumberFormat::BQ => 8,
            NumberFormat::BH => 2,
            NumberFormat::BB => 1,
        }
    }

    fn read<R: Read>(&self, r: &mut R) -> Result<u64, std::io::Error> {
        match self {
            NumberFormat::BI => Ok(r.read_u32::<BigEndian>()?.into()),
            NumberFormat::BQ => Ok(r.read_u64::<BigEndian>()?),
            NumberFormat::BH => Ok(r.read_u16::<BigEndian>()?.into()),
            NumberFormat::BB => Ok(r.read_u8()?.into()),
        }
    }

    fn read_buff(&self, buf: &[u8]) -> Result<u64, std::io::Error> {
        let mut buf = Cursor::new(buf);
        self.read(&mut buf)
    }
}

fn unescape_entities(text: &str) -> String {
    // def _unescape_entities(text):
    //     """
    //     unescape offending tags < > " &
    //     """
    //     text = text.replace(b'&lt;', b'<')
    //     text = text.replace(b'&gt;', b'>')
    //     text = text.replace(b'&quot;', b'"')
    //     text = text.replace(b'&amp;', b'&')
    //     return text

    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

fn decrypt_regcode_by_userid(reg_code: &[u8], userid: &[u8]) -> Vec<u8> {
    let userid_digest = ripemd128(userid);
    let mut s20 = Salsa20::new(Some(&userid_digest), Some(&[0; 8]), 8);
    s20.encrypt_bytes(reg_code)
}

fn encrypt_uuid64(uuid: &str) -> Vec<u8> {
    let mid = (uuid.len() + 1) / 2;

    let first_half = &uuid[..mid];
    let second_half = &uuid[mid..];

    let first_hash = xxh64(first_half.as_bytes(), 0);
    let second_hash = xxh64(second_half.as_bytes(), 0);

    let mut encrypted_key = first_hash.to_be_bytes().to_vec();
    encrypted_key.extend(second_hash.to_be_bytes());
    encrypted_key
}

fn fast_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    // XOR decryption

    let mut b = data.to_vec();
    let key = key.to_vec();
    let mut previous = 0x36;

    for i in 0..b.len() {
        let t = (b[i] >> 4 | b[i] << 4) & 0xff;
        let t = t ^ previous ^ (i as u8 & 0xff) ^ key[i % key.len()];
        previous = b[i];
        b[i] = t;
    }

    b
}

fn salsa_decrypt(data: &[u8], encrypt_key: &[u8]) -> Vec<u8> {
    // salsa20 (8 rounds) decryption

    let mut s20 = Salsa20::new(Some(&encrypt_key), Some(&[0; 8]), 8);
    s20.encrypt_bytes(data)
}

fn lzo_decompress(input: &[u8], len: usize) -> Vec<u8> {
    let input = if input.starts_with(b"\xf0") {
        &input[5..]
    } else {
        input
    };

    let mut dst = vec![0u8; len];
    let (dst, err) = LZOContext::decompress_to_slice(&input, &mut dst);
    assert!(
        err == rust_lzo::LZOError::OK,
        "decompress error: {:?}",
        err as i32
    );

    dst.to_vec()
}

fn zlib_decompress(data: &[u8]) -> Vec<u8> {
    // zlib decompression
    // notifiy
    let mut d = ZlibDecoder::new(data);
    let mut decompressed_bytes = Vec::new();

    d.read_to_end(&mut decompressed_bytes).unwrap();

    decompressed_bytes
}

type Item = (Vec<u8>, Vec<u8>);

pub struct MDict {
    fname: String,
    encoding: String,
    encrypted_key: Option<Vec<u8>>,
    encrypt: i32,
    header: HashMap<String, String>,
    substyle: bool,
    stylesheet: HashMap<String, (String, String)>,
    key_list: Vec<(u32, Vec<u8>)>,
    version: f32,
    key_block_offset: u64,
    // number_width: u32,
    number_format: NumberFormat,
    record_block_offset: u64,
    record_index_offset: u64,
    key_data_offset: u64,
    key_index_offset: u64,
    num_entries: u32,
}

struct MdictIteratorData<'a> {
    mdict: &'a mut MDict,
    buff_reader: Option<BufReader<File>>,
    record_block_size: u64,
    record_block_info_list: VecDeque<(usize, usize)>,
    size_counter: usize,

    key_list_index: usize,
    record_block: Option<Vec<u8>>,
    record_block_offset: usize,
}

impl<'a> MdictIteratorData<'a> {
    fn new(mdict: &'a mut MDict) -> Self {
        MdictIteratorData {
            mdict,
            buff_reader: None,
            record_block_size: 0,
            record_block_info_list: VecDeque::new(),
            size_counter: 0,
            key_list_index: 0,
            record_block: None,
            record_block_offset: 0,
        }
    }
}

struct MDictIteratorV1V2<'a> {
    data: MdictIteratorData<'a>,
}

impl<'a> MDictIteratorV1V2<'a> {
    fn new(mdict: &'a mut MDict) -> Self {
        let mut iter = MDictIteratorV1V2 {
            data: MdictIteratorData::new(mdict),
        };
        iter.init();
        iter
    }

    fn init(&mut self) -> std::io::Result<()> {
        let mut f = File::open(&self.data.mdict.fname)?;

        self.data.buff_reader = Some(BufReader::new(f));
        let mut f = self.data.buff_reader.as_mut().unwrap();

        f.seek(SeekFrom::Start(self.data.mdict.record_block_offset))?;

        let num_record_blocks = self.data.mdict.read_number(&mut f);
        let num_entries = self.data.mdict.read_number(&mut f);
        assert_eq!(num_entries, self.data.mdict.num_entries as u64);

        let record_block_info_size = self.data.mdict.read_number(&mut f);

        self.data.record_block_size = self.data.mdict.read_number(&mut f);

        // Record block info section
        let mut check_record_block_info_size = 0;
        for _ in 0..num_record_blocks {
            let compressed_size = self.data.mdict.read_number(&mut f) as usize;
            let decompressed_size = self.data.mdict.read_number(&mut f) as usize;
            self.data
                .record_block_info_list
                .push_back((compressed_size, decompressed_size));
            check_record_block_info_size += self.data.mdict.number_format.size() * 2;
        }
        assert_eq!(check_record_block_info_size as u64, record_block_info_size);

        Ok(())
    }

    fn get_item(&mut self) -> std::io::Result<Item> {
        if let Some(record_block) = &self.data.record_block {
            let record_block_len = record_block.len();
            if let Some((record_start, key_text)) =
                self.data.mdict.key_list.get(self.data.key_list_index)
            {
                let record_start = *record_start as usize;

                // Reach the end of current record block
                if record_start - self.data.record_block_offset >= record_block_len {
                    self.data.record_block_offset += record_block_len;
                    self.data.record_block = None;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "No more items",
                    ));
                }

                // Record end index
                let record_end = if self.data.key_list_index < self.data.mdict.key_list.len() - 1 {
                    self.data.mdict.key_list[self.data.key_list_index + 1].0 as usize
                } else {
                    record_block_len + self.data.record_block_offset
                };

                self.data.key_list_index += 1;
                let start = record_start - self.data.record_block_offset;
                let end = record_end - self.data.record_block_offset;
                let data = &record_block[start..end];

                return Ok((key_text.clone(), self.data.mdict.treat_record_data(data)));
            }
            self.data.record_block_offset += record_block_len;
            self.data.record_block = None;
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No more items",
        ))
    }
}

impl<'a> Iterator for MDictIteratorV1V2<'a> {
    type Item = Item;

    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(item) = self.get_item() {
            return Some(item);
        }

        while let Some((compressed_size, decompressed_size)) =
            self.data.record_block_info_list.pop_front()
        {
            let mut f = self.data.buff_reader.as_mut().unwrap();

            let mut compressed_data = vec![0; compressed_size];
            f.read_exact(compressed_data.as_mut_slice()).unwrap();
            self.data.size_counter += compressed_size;

            let record_block = self
                .data
                .mdict
                .decode_block(&compressed_data, decompressed_size as u32);
            self.data.record_block = Some(record_block);

            if let Ok(item) = self.get_item() {
                return Some(item);
            }
        }
        assert_eq!(self.data.size_counter, self.data.record_block_size as usize);
        None
    }
}

struct MDictIteratorV3<'a> {
    data: MdictIteratorData<'a>,
    record_index: Vec<(u32, u32)>,
    num_record_blocks: u32,
    num_record_blocks_idx: u32,
}

impl<'a> MDictIteratorV3<'a> {
    fn new(mdict: &'a mut MDict) -> Self {
        let mut iterv3 = MDictIteratorV3 {
            data: MdictIteratorData::new(mdict),
            record_index: Vec::new(),
            num_record_blocks: 0,
            num_record_blocks_idx: 0,
        };
        iterv3.init().expect("Failed to initialize MDictIteratorV3");
        iterv3
    }

    fn init(&mut self) -> std::io::Result<()> {
        self.data.buff_reader = Some(BufReader::new(File::open(&self.data.mdict.fname)?));
        let mut f = self.data.buff_reader.as_mut().unwrap();

        self.record_index = self.data.mdict.read_record_index(&mut f)?;

        f.seek(SeekFrom::Start(self.data.mdict.record_block_offset))?;
        self.num_record_blocks = self.data.mdict.read_u32(&mut f);
        let _ = self.data.mdict.read_number(&mut f);

        Ok(())
    }

    fn get_record_block(&mut self) -> std::io::Result<Vec<u8>> {
        let mut f = self.data.buff_reader.as_mut().unwrap();
        let decompressed_size = self.data.mdict.read_u32(&mut f);
        let compressed_size = self.data.mdict.read_u32(&mut f);

        while self.num_record_blocks_idx < self.num_record_blocks {
            let idx = self.num_record_blocks_idx as usize;
            self.num_record_blocks_idx += 1;

            // Check against the record index information
            if (compressed_size + 8, decompressed_size) != self.record_index[idx] {
                let compressed_size = self.record_index[idx].0 - 8;
                // Skip to the next block
                println!("Skip (potentially) damaged record block");
                f.seek(SeekFrom::Current(compressed_size as i64))?;
                continue;
            }

            let mut compressed_data = vec![0; compressed_size as usize];
            f.read_exact(&mut compressed_data)?;
            return Ok(self
                .data
                .mdict
                .decode_block(&compressed_data, decompressed_size));
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No more record blocks",
        ))
    }

    fn get_item(&mut self) -> std::io::Result<Item> {
        if self.data.record_block.is_none() {
            self.data.record_block = self.get_record_block().ok();
        }

        if let Some(record_block) = &self.data.record_block {
            let record_block_len = record_block.len();

            let idx = self.data.key_list_index;

            let offset = self.data.record_block_offset;

            if let Some((record_start, key_text)) = self.data.mdict.key_list.get(idx) {
                let record_start = *record_start as usize;

                // Reach the end of current record block
                if record_start - offset >= record_block_len {
                    self.data.record_block = None;
                    self.data.record_block_offset += record_block_len;
                    return self.get_item();
                }

                let record_end = if idx < self.data.mdict.key_list.len() - 1 {
                    self.data.mdict.key_list[idx + 1].0 as usize
                } else {
                    record_block_len + offset
                };

                self.data.key_list_index += 1;
                let data = record_block[record_start - offset..record_end - offset].to_vec();
                return Ok((key_text.clone(), self.data.mdict.treat_record_data(&data)));
            } else {
                self.data.record_block = None;
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No more items",
        ))
    }
}

impl<'a> Iterator for MDictIteratorV3<'a> {
    type Item = Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.get_item().ok()
    }
}

struct MDictIterator<'a> {
    iter: Box<dyn Iterator<Item = Item> + 'a>,
}

impl<'a> MDictIterator<'a> {
    fn new(mdict: &'a mut MDict) -> Self {
        if mdict.version < 3.0 {
            MDictIterator {
                iter: Box::new(MDictIteratorV1V2::new(mdict)),
            }
        } else {
            MDictIterator {
                iter: Box::new(MDictIteratorV3::new(mdict)),
            }
        }
    }
}

impl<'a> Iterator for MDictIterator<'a> {
    type Item = Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl MDict {
    pub fn new(
        fname: &str,
        encoding: Option<&str>,
        passcode: Option<(&[u8], &[u8])>,
        substyle: Option<bool>,
    ) -> Self {
        let mut mdict = MDict {
            fname: fname.to_string(),
            encoding: encoding.unwrap_or("").to_string(),
            encrypted_key: None,
            encrypt: 0,
            header: HashMap::new(),
            substyle: substyle.unwrap_or(false),
            stylesheet: HashMap::new(),
            key_list: Vec::new(),
            version: 0.0,
            key_block_offset: 0,
            number_format: NumberFormat::BQ,
            record_block_offset: 0,
            record_index_offset: 0,
            key_data_offset: 0,
            key_index_offset: 0,
            num_entries: 0,
        };

        if fname.ends_with(".mdx") {
            mdict.init_mdx(passcode);
        } else if fname.ends_with(".mdd") {
            mdict.init_mdd(passcode);
        } else {
            panic!("Unknown file type");
        }

        mdict
    }

    pub fn keys<'a>(&'a mut self) -> impl Iterator<Item = Vec<u8>> + 'a {
        self.key_list.iter().map(|(_, v)| v.to_vec()).into_iter()
    }

    pub fn items<'a>(&'a mut self) -> impl Iterator<Item = Item> + 'a {
        MDictIterator::new(self)
    }

    pub fn header(&self) -> &HashMap<String, String> {
        &self.header
    }

    fn init(&mut self, passcode: Option<(&[u8], &[u8])>) {
        self.header = self.read_header();

        // Decrypt regcode to get the encrypted key
        if let Some((regcode, userid)) = passcode {
            self.encrypted_key = Some(decrypt_regcode_by_userid(regcode, userid));
        } else if self.version >= 3.0 {
            if let Some(uuid) = self.header.get("UUID") {
                if !uuid.is_empty() {
                    self.encrypted_key = Some(encrypt_uuid64(uuid));
                }
            }
        }

        self.key_list = self.read_keys();
    }

    fn init_mdx(&mut self, passcode: Option<(&[u8], &[u8])>) {
        self.init(passcode);
    }

    fn init_mdd(&mut self, passcode: Option<(&[u8], &[u8])>) {
        self.encoding = "UTF-16".to_string();
        self.init(passcode);
    }

    fn read_record_index<R: Read + Seek>(&mut self, f: &mut R) -> std::io::Result<Vec<(u32, u32)>> {
        f.seek(SeekFrom::Start(self.record_index_offset))?;

        let num_record_blocks = self.read_u32(f);
        let _num_bytes = self.read_number(f);

        let mut record_index = Vec::new();
        for _ in 0..num_record_blocks {
            let decompressed_size = self.read_u32(f);
            let compressed_size = self.read_u32(f) as usize;
            let mut compressed_data = vec![0; compressed_size];
            f.read_exact(&mut compressed_data)?;
            let record_block = self.decode_block(&compressed_data, decompressed_size);
            if record_block.len() % 16 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid record block",
                ));
            }

            let mut j = 0;
            while j < record_block.len() {
                let block_size = (&record_block[j..j + 8]).read_u64::<BigEndian>()?;
                let decompressed_size = (&record_block[j + 8..j + 16]).read_u64::<BigEndian>()?;
                record_index.push((block_size as u32, decompressed_size as u32));
                j += 16;
            }
        }
        Ok(record_index)
    }

    fn read_header(&mut self) -> HashMap<String, String> {
        let mut f = File::open(self.fname.clone()).expect("Unable to open file");

        // Number of bytes of header text
        let mut header_bytes_size = f
            .read_u32::<BigEndian>()
            .expect("Unable to read header size");

        let mut header_bytes = vec![0u8; header_bytes_size as usize];
        f.read_exact(&mut header_bytes).unwrap();

        // 4 bytes: adler32 checksum of header, in little endian
        let adler32 = f
            .read_u32::<LittleEndian>()
            .expect("Unable to read adler32 checksum");

        assert_eq!(adler32, adler32_slice(&header_bytes));

        // Mark down key block offset
        self.key_block_offset = f
            .seek(SeekFrom::Current(0))
            .expect("Unable to get file position");

        let header_text = if header_bytes.ends_with(&[0x00, 0x00]) {
            // convert utf16 to utf8
            let (cow, _, _) = UTF_16LE.decode(&header_bytes[..header_bytes.len() - 2]);
            cow.to_string()
        } else {
            // Use the header bytes as they are
            std::str::from_utf8(&header_bytes[..header_bytes.len() - 1])
                .expect("Failed to convert header bytes to string")
                .to_string()
        };

        let header_tag = self.parse_header(&header_text);

        if self.encoding.is_empty() {
            if let Some(encoding) = header_tag.get("Encoding") {
                self.encoding = encoding.to_uppercase();
            } else {
                self.encoding = "UTF-8".to_string();
            }
            if ["GBK", "GB2312"].contains(&self.encoding.as_str()) {
                self.encoding = "GB18030".to_string();
            }
        }

        if !header_tag.contains_key("Encrypted") || header_tag.get("Encrypted").unwrap() == "No" {
            self.encrypt = 0;
        } else if header_tag["Encrypted"] == "Yes" {
            self.encrypt = 1;
        } else {
            self.encrypt = header_tag["Encrypted"]
                .parse::<i32>()
                .expect("Failed to parse encryption value");
        }

        if let Some(ss) = header_tag.get("StyleSheet") {
            for chunk in ss.split('\n').collect::<Vec<_>>().chunks(3) {
                if let [key, start, end] = chunk {
                    self.stylesheet.insert(
                        (*key).to_string(),
                        ((*start).to_string(), (*end).to_string()),
                    );
                }
            }
        }

        self.version = header_tag
            .get("GeneratedByEngineVersion")
            .unwrap()
            .parse::<f32>()
            .expect("Failed to parse version");
        if self.version < 2.0 {
            self.number_format = NumberFormat::BI;
        } else {
            self.number_format = NumberFormat::BQ;
            if self.version >= 3.0 {
                self.encoding = "UTF-8".to_string();
            }
        }

        header_tag
    }

    fn parse_header(&mut self, header_text: &str) -> HashMap<String, String> {
        // def _parse_header(self, header):
        //     """
        //     extract attributes from <Dict attr="value" ... >
        //     """
        //     taglist = re.findall(rb'(\w+)="(.*?)"', header, re.DOTALL)
        //     tagdict = {}
        //     for key, value in taglist:
        //         tagdict[key] = _unescape_entities(value)
        //     return tagdict

        let mut header = HashMap::new();

        let re = Regex::new(r#"(\w+)="(.*?)""#).unwrap();
        for cap in re.captures_iter(header_text) {
            let key = cap.get(1).unwrap().as_str();
            let value = cap.get(2).unwrap().as_str();
            header.insert(key.to_string(), unescape_entities(value));
        }

        header
    }

    fn read_keys(&mut self) -> Vec<(u32, Vec<u8>)> {
        if self.version >= 3.0 {
            self.read_keys_v3()
        } else if (self.encrypt & 0x01) != 0 && self.encrypted_key.is_none() {
            self.read_keys_brutal()
        } else {
            self.read_keys_v1v2()
        }
    }

    fn read_number<R: Read>(&mut self, f: &mut R) -> u64 {
        self.number_format.read(f).unwrap()
    }

    fn read_u64<R: Read>(&mut self, f: &mut R) -> u64 {
        f.read_u64::<BigEndian>().unwrap()
    }

    fn read_u32<R: Read>(&mut self, f: &mut R) -> u32 {
        f.read_u32::<BigEndian>().unwrap()
    }

    fn read_keys_v3(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut f = File::open(self.fname.clone()).expect("Unable to open file");
        f.seek(SeekFrom::Start(self.key_block_offset))
            .expect("Unable to seek to key block offset");

        loop {
            let block_type = self.read_u32(&mut f);
            let block_size = self.read_number(&mut f);
            let block_offset = f.seek(SeekFrom::Current(0)).unwrap();

            match block_type {
                0x01000000 => self.record_block_offset = block_offset,
                0x02000000 => self.record_index_offset = block_offset,
                0x03000000 => self.key_data_offset = block_offset,
                0x04000000 => self.key_index_offset = block_offset,
                _ => {
                    panic!("Unknown block type: {}", block_type);
                }
            }
            f.seek(SeekFrom::Current(block_size as i64)).unwrap();
            if f.read_exact(&mut [0u8; 4]).is_ok() {
                f.seek(SeekFrom::Current(-4)).unwrap();
            } else {
                break;
            }
        }

        f.seek(SeekFrom::Start(self.key_data_offset)).unwrap();
        let num = self.read_u32(&mut f);
        let _ = self.read_number(&mut f);

        let mut key_list = Vec::new();
        for _ in 0..num {
            let decompressed_size = self.read_u32(&mut f);
            let compressed_size = self.read_u32(&mut f);

            let mut block_data = vec![0u8; compressed_size as usize];
            f.read_exact(&mut block_data)
                .expect("Unable to read block data");

            let decompressed_block_data = self.decode_block(&block_data, decompressed_size);
            key_list.extend(self.split_key_block(decompressed_block_data.as_slice()));
        }

        self.num_entries = key_list.len() as u32;
        key_list
    }

    fn read_keys_brutal(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut f = File::open(self.fname.clone()).expect("Unable to open file");

        f.seek(SeekFrom::Start(self.key_block_offset))
            .expect("Unable to seek to key block offset");

        let (num_bytes, key_block_type) = if self.version >= 2.0 {
            (8 * 5 + 4, b"\x02\x00\x00\x00")
        } else {
            (4 * 4, b"\x01\x00\x00\x00")
        };

        let mut block = vec![0u8; num_bytes as usize];
        f.read(&mut block).expect("Unable to read block data");

        let mut key_block_info = vec![0u8; 8];
        f.read(&mut key_block_info)
            .expect("Unable to read key block info");
        if self.version >= 2.0 {
            assert_eq!(&key_block_info[..4], b"\x02\x00\x00\x00");
        }

        loop {
            let fpos = f.seek(SeekFrom::Current(0)).unwrap();
            let mut t = vec![0u8; 1024];
            f.read(&mut t).expect("Unable to read block data");
            if let Some(index) = t.iter().position(|&x| x == key_block_type[0]) {
                key_block_info.extend(&t[..index]);
                f.seek(SeekFrom::Start(fpos + index as u64)).unwrap();
                break;
            } else {
                key_block_info.extend(&t);
            }
        }

        let key_block_info_list = self.decode_key_block_info(&key_block_info);
        let key_block_size: u32 = key_block_info_list.iter().map(|(size, _)| size).sum();

        let mut key_block_compressed = vec![0u8; key_block_size as usize];

        let mut key_list = Vec::new();
        if f.read(&mut key_block_compressed).is_ok() {
            key_list = self.decode_key_block(&key_block_compressed, &key_block_info_list);
        }
        self.record_block_offset = f.seek(SeekFrom::Current(0)).unwrap();
        self.num_entries = key_list.len() as u32;
        key_list
    }

    fn read_keys_v1v2(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut f = File::open(self.fname.clone()).expect("Unable to open file");
        f.seek(SeekFrom::Start(self.key_block_offset))
            .expect("Unable to seek to key block offset");

        let num_bytes = if self.version >= 2.0 { 8 * 5 } else { 4 * 4 };
        let mut block = vec![0u8; num_bytes as usize];
        f.read_exact(&mut block).expect("Unable to read block data");

        if (self.encrypt & 0x01) != 0 {
            if let Some(ref ek) = self.encrypted_key {
                block = salsa_decrypt(&block, ek);
            }
        }
        let mut sf = Cursor::new(&block);
        let num_key_blocks = self.read_number(&mut sf);
        self.num_entries = self.read_number(&mut sf) as u32;
        if self.version >= 2.0 {
            // skip the size of key block info section (decompressed size)
            self.read_number(&mut sf);
        }
        let key_block_info_size = self.read_number(&mut sf);
        let key_block_size = self.read_number(&mut sf);
        if self.version >= 2.0 {
            let adler32 = f.read_u32::<BigEndian>().unwrap();
            assert_eq!(adler32, adler32_slice(&block) & 0xffffffffu32);
        }

        let mut key_block_info = vec![0u8; key_block_info_size as usize];
        f.read_exact(&mut key_block_info)
            .expect("Unable to read key block info");
        let key_block_info_list = self.decode_key_block_info(&key_block_info);
        assert_eq!(num_key_blocks as usize, key_block_info_list.len());

        let mut key_block_compressed = vec![0u8; key_block_size as usize];
        f.read_exact(&mut key_block_compressed)
            .expect("Unable to read key block compressed data");
        let key_list = self.decode_key_block(&key_block_compressed, &key_block_info_list);
        self.record_block_offset = f.seek(SeekFrom::Current(0)).unwrap();
        key_list
    }

    fn decode_key_block(
        &mut self,
        key_block_compressed: &[u8],
        key_block_info_list: &[(u32, u32)],
    ) -> Vec<(u32, Vec<u8>)> {
        let mut key_list = Vec::new();

        let mut i = 0;
        for &(block_compressed_size, block_decompressed_size) in key_block_info_list {
            let key_block = self.decode_block(
                &key_block_compressed[i..i + block_compressed_size as usize].to_vec(),
                block_decompressed_size,
            );
            key_list.extend(self.split_key_block(&key_block));
            i += block_compressed_size as usize;
        }

        key_list
    }

    fn treat_record_data(&self, data: &[u8]) -> Vec<u8> {
        if self.fname.ends_with(".mdd") {
            data.to_vec()
        } else {
            // # def _treat_record_data(self, data):
            // #     # convert to utf-8
            // #     data = data.decode(self._encoding, errors='ignore').strip(u'\x00').encode('utf-8')
            // #     # substitute styles
            // #     if self._substyle and self._stylesheet:
            // #         data = self._substitute_stylesheet(data)
            // #     return data

            // # convert to utf-8
            let encoding = Encoding::for_label(self.encoding.as_bytes()).unwrap();
            let decoded = encoding.decode(&data).0;
            let utf8encode = UTF_8.encode(decoded.trim_matches('\u{0000}')).0;
            if self.substyle && !self.stylesheet.is_empty() {
                self.substitute_stylesheet(&utf8encode)
            } else {
                utf8encode.to_vec()
            }
        }
    }

    fn substitute_stylesheet(&self, data: &[u8]) -> Vec<u8> {
        let re = BytesRegex::new(r"\d+").unwrap();

        let txt_list: Vec<&[u8]> = re.split(data).collect();
        let txt_tag: Vec<&[u8]> = re.find_iter(data).map(|m| m.as_bytes()).collect();

        let mut txt_styled = Vec::with_capacity(data.len());
        txt_styled.extend_from_slice(txt_list[0]);

        for (j, &p) in txt_list.iter().enumerate().skip(1) {
            if let Some(style) = self
                .stylesheet
                .get(std::str::from_utf8(&txt_tag[j - 1][1..txt_tag[j - 1].len() - 1]).unwrap())
            {
                txt_styled.extend_from_slice(style.0.as_bytes());
                txt_styled.extend_from_slice(p);
                txt_styled.extend_from_slice(style.1.as_bytes());
                if !p.is_empty() && p.last() == Some(&b'\n') {
                    txt_styled.push(b'\r');
                }
                txt_styled.push(b'\n');
            }
        }
        txt_styled
    }

    fn decode_key_block_info(&mut self, key_block_info: &[u8]) -> Vec<(u32, u32)> {
        let mut block_info = key_block_info.to_vec();
        if self.version >= 2.0 {
            assert!(block_info.starts_with(b"\x02\x00\x00\x00"));
            if self.encrypt & 0x02 != 0 {
                let mut key = block_info[4..8].to_vec();
                key.extend_from_slice(&[0x95, 0x36, 0x00, 0x00]); // Directly use the constant
                key = ripemd128(&key);
                let mut new_block_info = block_info[..8].to_vec();
                new_block_info.extend(fast_decrypt(&block_info[8..], &key));
                block_info = new_block_info;
            }
            let adler2 = BigEndian::read_u32(&block_info[4..8]);
            block_info = zlib_decompress(&block_info[8..]);
            assert_eq!(adler2, adler32_slice(&block_info) & 0xffffffffu32);
        }

        let (byte_format, text_term) = if self.version >= 2.0 {
            (NumberFormat::BH, 1)
        } else {
            (NumberFormat::BB, 0)
        };

        let mut key_block_info_list = Vec::new();
        let mut cursor = Cursor::new(&block_info);

        while cursor.position() < block_info.len() as u64 {
            // number of entries in current key block
            if let Ok((block_compressed_size, block_decompressed_size)) =
                self.get_key_compressed_size(&byte_format, text_term, &mut cursor)
            {
                key_block_info_list.push((block_compressed_size, block_decompressed_size));
            }
        }

        key_block_info_list
    }

    fn get_key_compressed_size<R: Read + Seek>(
        &mut self,
        byte_format: &NumberFormat,
        text_term: i64,
        mut cursor: &mut R,
    ) -> Result<(u32, u32), std::io::Error> {
        // number of entries in current key block
        self.number_format.read(&mut cursor)?;

        let text_head_size = byte_format.read(&mut cursor)? as i64;

        if self.encoding == "UTF-16" {
            cursor.seek(SeekFrom::Current((text_head_size + text_term) * 2))?;
        } else {
            cursor.seek(SeekFrom::Current(text_head_size + text_term))?;
        }
        let text_tail_size = byte_format.read(&mut cursor)? as i64;
        if self.encoding == "UTF-16" {
            cursor.seek(SeekFrom::Current((text_tail_size + text_term) * 2))?;
        } else {
            cursor.seek(SeekFrom::Current(text_tail_size + text_term))?;
        }
        let block_compressed_size = self.number_format.read(&mut cursor)?;
        let block_decompressed_size = self.number_format.read(&mut cursor)?;
        Ok((block_compressed_size as u32, block_decompressed_size as u32))
    }

    fn split_key_block(&mut self, key_block: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut key_list = Vec::new();
        let mut key_start_index = 0;

        while key_start_index < key_block.len() {
            // the corresponding record's offset in record block
            let key_id = self.number_format.read_buff(
                &key_block[key_start_index..key_start_index + self.number_format.size()],
            );
            if key_id.is_err() {
                break;
            }
            // key text ends with '\x00'
            let (delimiter, width) = if self.encoding == "UTF-16" {
                (b"\x00\x00".to_vec(), 2)
            } else {
                (b"\x00".to_vec(), 1)
            };

            let mut i = key_start_index + self.number_format.size();
            let mut key_end_index = key_block.len();
            while i < key_block.len() {
                if &key_block[i..i + width] == delimiter {
                    key_end_index = i;
                    break;
                }
                i += width;
            }

            let (decode_str, _, _) = Encoding::for_label(self.encoding.as_bytes())
                .unwrap()
                .decode(&key_block[key_start_index + self.number_format.size()..key_end_index]);

            let key_text = decode_str.trim().as_bytes().to_vec();

            key_start_index = key_end_index + width;
            key_list.push((key_id.unwrap() as u32, key_text));
        }

        key_list
    }

    fn decode_block(&mut self, block_data: &Vec<u8>, decompressed_size: u32) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(block_data);

        let info = cursor.read_i32::<LittleEndian>().unwrap();
        let compression_method = info & 0xf;
        let encryption_method = (info >> 4) & 0xf;
        let encryption_size = (info >> 8) & 0xff;

        let adler32 = cursor.read_u32::<BigEndian>().unwrap();
        let encrypted_key = if self.encrypted_key.is_none() {
            ripemd128(&block_data[4..8])
        } else {
            self.encrypted_key.clone().unwrap()
        };

        let data = block_data[8..].to_vec();

        let decrypted_block = match encryption_method {
            0 => data,
            1 => {
                let mut block = fast_decrypt(&data[..encryption_size as usize], &encrypted_key);
                block.extend(data[encryption_size as usize..].to_vec());
                block
            }
            2 => {
                let mut block = salsa_decrypt(&data[..encryption_size as usize], &encrypted_key);
                block.extend(data[encryption_size as usize..].to_vec());
                block
            }
            _ => panic!("encryption method {} not find", encryption_method),
        };

        if self.version >= 3.0 {
            assert_eq!(
                format!("{:x}", adler32),
                format!("{:x}", adler32_slice(&decrypted_block) & 0xffffffff)
            )
        }

        let decompressed_block = match compression_method {
            0 => decrypted_block,
            1 => lzo_decompress(&decrypted_block, decompressed_size as usize),
            2 => zlib_decompress(&decrypted_block),
            _ => panic!("compression method {} not find.", compression_method),
        };

        if self.version < 3.0 {
            assert_eq!(
                format!("{:x}", adler32),
                format!("{:x}", adler32_slice(&decompressed_block) & 0xffffffff)
            )
        }

        decompressed_block
    }
}
