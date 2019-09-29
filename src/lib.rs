//! # TOTP crate
//!
//! `TOTP` project is used for calculate a [Time-based One-time Password](https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm)
//! For more infomation, please check the link above
//! **Note: This crate takes base32-encrypted secret

pub mod error;

use error::*;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::md5::Md5;
use chrono::prelude::*;
use crypto::mac::Mac;

/// A TOTP Unit which contains some elements used to calculate totp
///
/// **Note:** 
/// 1. time_step's unit is second
/// 2. epoch_start is a `i64` the different milliseconds from 1970 0101 00:00;
///
/// # Example
/// ```
/// use totp::*;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>>{
///     let x = "XW7HPZJ2L3AMPWQN";
///     let totp = TOTP::default(x);
///     let code = totp.get_code()?;
///     let left_time = totp.get_left_time();
///     println!("code: {:06}\r\nleft time: {}s", code, left_time);
///     Ok(())
///}
/// ```

pub struct TOTP <'a> {
    secret: &'a [u8],
    time_step: f64, 
    epoch_start: i64,
    encryption: Encryption,
}


/// Encryption used in totp, can be `sha1` or `md5`
pub enum Encryption {
    SHA1,
    MD5,
}

impl<'a> TOTP<'a>{
    pub fn new(secret: &'a [u8], time_step: f64, epoch_start: i64, encryption: Encryption) -> Self {
        Self {
            secret,
            time_step,
            epoch_start,
            encryption,
        }
    }

    /// create a new TOTP with default settings
    /// 1. time_step: 30 seconds
    /// 2. epoch_start: 0
    /// 3. encryption: SHA1
    pub fn default(secret: &'a [u8]) -> Self {
        Self {
            secret,
            time_step: 30.0,
            epoch_start: 0,
            encryption: Encryption::SHA1,
        }
    }
    
    /// get result code of current totp
    /// # Error
    /// when parse secret occurs error
    pub fn get_code(&self) -> Result<u32, ParseError>{
        let time_count:i64 = (((Utc::now().timestamp_millis() - self.epoch_start) as f64/1000.0 + 0.5)/self.time_step) as i64;
        let code = match self.encryption {
            Encryption::SHA1 => {
                let mut hmac = Hmac::new(Sha1::new(), self.secret);
                hmac.input(&time_count.to_be_bytes());
                let result = hmac.result();
                result.code().to_vec()
            },
            Encryption::MD5 => {
                let mut hmac = Hmac::new(Md5::new(), self.secret);
                hmac.input(&time_count.to_be_bytes());
                let result = hmac.result();
                result.code().to_vec()
            }
        };
        let offset = (code.last().unwrap() & 0x0f) as usize;
        let mut otp = (&code[offset..offset+4]).to_vec();
        otp[0] = otp[0] & 0x7f;
        let hex:String = otp.iter().map(|chunk| {
            format!("{:02X}", chunk)
        }).collect();
        Ok(u32::from_str_radix(&hex, 16)?%1000000)
    }

    /// get left valid of current totp
    pub fn get_left_time(&self) -> f64{
        let time = ((Utc::now().timestamp_millis() - self.epoch_start) as f64/1000.0 + 0.5) as i64;
        let time_used = time as f64 % self.time_step;
        self.time_step - time_used
    }

}

/// base32 decode, return raw data with Vec<u8> type
/// # Error
/// 1. When there is a invalid base32 char
/// 2. Parse str to u8 occurs error
pub fn base32_to_secret(s: &str) -> Result<Vec<u8>, ParseError> {
    let mut all_bits = String::new();
    for b in s.bytes() {
        let x:u8;
        if b >= 65 && b<=90 {
            x = b-65;
        } else if b >= 50 && b<= 55 {
            x = b-50+26;
        } else {
            return Err(ParseError::InvalidBase32Char);
        }
        let bits = format!("{:05b}", x); 
        all_bits.push_str(&bits);
    }
    let all_chars:Vec<char> = all_bits.chars().collect();
    let all_u8:Result<Vec<u8>, _> = all_chars.chunks(8).map(|chunk| {
        let s:String = chunk.iter().collect();
        u8::from_str_radix(&s, 2)
    }).collect();
    Ok(all_u8?)
}
