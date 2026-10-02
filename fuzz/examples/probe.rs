use sqlite3mc_src_fuzz::{run, Algorithm, Case, Config, Key, Op, Side, Table};

fn main() {
    for writer in [Side::Sqlite3mc, Side::SqlCipher] {
        for compatibility in 1..=4 {
            for kdf in [
                None,
                Some(Algorithm::Sha1),
                Some(Algorithm::Sha256),
                Some(Algorithm::Sha512),
            ] {
                for hmac in [None, Some(false), Some(true)] {
                    let c = Case {
                        writer,
                        config: Config {
                            compatibility,
                            page_size: None,
                            kdf_algorithm: kdf,
                            hmac_algorithm: None,
                            hmac,
                            key: Key::Passphrase {
                                bytes: b"pass".to_vec(),
                                kdf_iter: 3,
                            },
                        },
                        ops: vec![Op::Create(Table::T0)],
                        damage: vec![],
                    };
                    let r = std::panic::catch_unwind(|| run(&c));
                    if r.is_err() {
                        println!("FAIL writer={writer:?} compat={compatibility} kdf={kdf:?} hmac={hmac:?}");
                    }
                }
            }
        }
    }
}
