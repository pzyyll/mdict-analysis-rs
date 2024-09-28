use base64::prelude::*;
use hex::FromHex;
use mdict_analysis::readmdict::MDict;
use std::collections::HashMap;

fn get_path(filename: &str) -> String {
    "tests/".to_string() + filename
}

#[test]
fn test_mdx() {
    let file = get_path("test.mdx");

    let mut m1 = MDict::new(file.as_str(), None, None, None);

    println!("mdx version: {:?}", m1.header());

    let dict = m1.items().map(|(k, v)| (k, v)).collect::<HashMap<_, _>>();

    assert_ne!(dict.len(), 0);
    assert_eq!(dict.len(), m1.keys().collect::<Vec<_>>().len());
    assert_eq!(
        dict.get("ärcher".as_bytes()),
        Some(&b"German order test\r\n".to_vec())
    );
}

#[test]
fn test_regcode_mdx() {
    let regcode = Vec::from_hex("366BC489F522542A8976ED39060E7D87").unwrap();
    let userid = b"pzyyll@gmail.com";
    let file = get_path("test_regcode.mdx");

    let mut m1 = MDict::new(file.as_str(), None, Some((&regcode, userid)), None);

    let dict = m1.items().map(|(k, v)| (k, v)).collect::<HashMap<_, _>>();

    assert_ne!(dict.len(), 0);
    assert_eq!(
        dict.get("ärcher".as_bytes()),
        Some(&b"German order test\r\n".to_vec())
    );
}

#[test]
fn test_mdd() {
    let mut md1 = MDict::new(r"tests/test.mdd", None, None, None);

    let dict = md1.items().map(|(k, v)| (k, v)).collect::<HashMap<_, _>>();

    for (key, value) in dict.iter() {
        let k = String::from_utf8_lossy(key);
        let v = BASE64_STANDARD.encode(value);
        println!(
            "key: {:?}, value: {:?}{}",
            k,
            &v[..v.len().min(10)],
            if v.len() > 10 { "..." } else { "" }
        );
    }

    assert_ne!(dict.len(), 0);
}
