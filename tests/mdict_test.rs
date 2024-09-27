use base64::prelude::*;
use hex::FromHex;
use mdict_analysis::readmdict::MDict;
use std::env;
use std::path::PathBuf;

fn get_path(filename: &str) -> String {
    let current_file_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("tests")
        .join(filename);

    current_file_path.to_str().unwrap().to_owned()
}

#[test]
fn test_mdx() {
    let file = get_path("test.mdx");

    let mut m1 = MDict::new(file.as_str(), None, None, None);

    for (key, value) in m1.items().iter().take(10) {
        let k = String::from_utf8_lossy(key);
        let val = String::from_utf8_lossy(value);
        println!("key: {:?}, value: {:?}", k, val);
    }

    assert_ne!(m1.items().len(), 0);
}

#[test]
fn test_regcode_mdx() {
    let regcode = Vec::from_hex("366BC489F522542A8976ED39060E7D87").unwrap();
    let userid = b"pzyyll@gmail.com";
    let file = get_path("test_regcode.mdx");

    let mut m1 = MDict::new(file.as_str(), None, Some((&regcode, userid)), None);

    assert_ne!(m1.items().len(), 0);
}

#[test]
fn test_mdd() {
    let file = get_path("test.mdd");

    let mut md1 = MDict::new(file.as_str(), None, None, None);

    for (key, value) in md1.items().iter() {
        let k = String::from_utf8_lossy(key);
        let v = BASE64_STANDARD.encode(value);
        println!(
            "key: {:?}, value: {:?}{}",
            k,
            &v[..v.len().min(10)],
            if v.len() > 10 { "..." } else { "" }
        );
    }

    assert_ne!(md1.items().len(), 0);
}
