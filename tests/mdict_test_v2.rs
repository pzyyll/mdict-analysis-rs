use mdict_analysis::readmdict::MDict;

#[test]
fn test_mdx() {
    let file = r"tests/demov2.mdx";
    let mut m1 = MDict::new(file, None, None, None);

    println!("mdx version: {:?}", m1.header());

    for (i, (k, v)) in m1.items().enumerate() {
        println!(
            "{}: {:?} => {:?}",
            i,
            std::str::from_utf8(&k),
            std::str::from_utf8(&v)
        );
    }

    assert_eq!(m1.keys().count(), 7);
}

#[test]
fn test_regcode_mdx() {
    // Force crack password
    let mut m1 = MDict::new(r"tests/demov2_reg.mdx", None, None, None);

    for (i, (k, v)) in m1.items().enumerate() {
        println!(
            "{}: {:?} => {:?}",
            i,
            std::str::from_utf8(&k),
            std::str::from_utf8(&v)
        );
    }

    assert_eq!(m1.keys().count(), 7);
}

#[test]
fn test_mdd() {
    let mut md1 = MDict::new(r"tests/demov2.mdd", None, None, None);

    let mut len = 0;
    for (i, (k, v)) in md1.items().enumerate() {
        println!(
            "{}: {:?} => {:?}",
            i,
            std::str::from_utf8(&k),
            v[0..10].to_vec()
        );
        len += 1;
    }

    assert_eq!(len, 6);
}
