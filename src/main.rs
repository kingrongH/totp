extern crate chrono;

use std::env;

use totp::*;


fn main() -> Result<(), Box<dyn std::error::Error>>{
    let mut arg = env::args();
    arg.next();
    let x = arg.next().unwrap();
    let key = base32_to_secret(&x)?;
    let totp = TOTP::default(&key);
    let code = totp.get_code();
    let left_time = totp.get_left_time();
    let code = code % 1000000;
    println!("code: {}\n left time: {}s", code, left_time);
    Ok(())
}

