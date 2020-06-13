//! # TOTP crate
//!
//! `TOTP` project is used for calculate a [Time-based One-time Password](https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm)
//! For more infomation, please check the link above

use error::*;
use chrono::prelude::*;
use hmac::{ Hmac, Mac, NewMac };
use md5::Md5;
use sha1::Sha1;
use generic_array::{ GenericArray, typenum::consts::U4 };

use std::collections::HashMap;

pub mod error;

type HmacSha1 = Hmac<Sha1>;
type HmacMd5 = Hmac<Md5>;

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
///     let key = base32_to_secret(&x)?;
///     let totp = TOTP::default(&key);
///     let code = totp.get_code()?;
///     let left_time = totp.get_left_time();
///     println!("code: {:06}\r\nleft time: {}s", code, left_time);
///     Ok(())
/// }
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
    pub fn get_code(&self) -> u32 {
        let time_count:i64 = (((Utc::now().timestamp_millis() - self.epoch_start) as f64/1000.0 + 0.5)/self.time_step) as i64;
        let code: GenericArray<u8, U4> = match self.encryption {
            Encryption::SHA1 => {
                let mut hmac = HmacSha1::new_varkey(self.secret.into()).unwrap();
                hmac.update(&time_count.to_be_bytes());
                let code = hmac.finalize().into_bytes();
                let offset = (code.last().unwrap() & 0x0f) as usize;
                GenericArray::from_slice(&code[offset..offset+4]).clone()
            },
            Encryption::MD5 => {
                let mut hmac = HmacMd5::new(self.secret.into());
                hmac.update(&time_count.to_be_bytes());
                let code = hmac.finalize().into_bytes();
                let offset = (code.last().unwrap() & 0x0f) as usize;
                GenericArray::from_slice(&code[offset..offset+4]).clone()
            }
        };
        let mut otp: [u8; 4] = code.into();
        otp[0] &= 0x7f;
        u32::from_be_bytes(otp)
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
/// When there is a invalid base32 char
pub fn base32_to_secret(s: &str) -> Result<Vec<u8>, ParseError> {
    const BASE32_VALUES: [[bool; 5]; 32] = [
        [false, false, false, false, false], [false, false, false, false, true], [false, false, false, true, false], [false, false, false, true, true],
        [false, false, true, false, false], [false, false, true, false, true], [false, false, true, true, false], [false, false, true, true, true],
        [false, true, false, false, false], [false, true, false, false, true], [false, true, false, true, false], [false, true, false, true, true],
        [false, true, true, false, false], [false, true, true, false, true], [false, true, true, true, false], [false, true, true, true, true],
        [true, false, false, false, false], [true, false, false, false, true], [true, false, false, true, false], [true, false, false, true, true],
        [true, false, true, false, false], [true, false, true, false, true], [true, false, true, true, false], [true, false, true, true, true],
        [true, true, false, false, false], [true, true, false, false, true], [true, true, false, true, false], [true, true, false, true, true],
        [true, true, true, false, false], [true, true, true, false, true], [true, true, true, true, false], [true, true, true, true, true]
    ];

    const BASE32_CHARS: [char; 32] = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H','I',
        'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
        'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
        'Z', '2', '3', '4', '5', '6', '7'
    ];

    let base32_map: HashMap<&char, &[bool; 5]> = BASE32_CHARS.iter().zip(BASE32_VALUES.iter()).collect();

    let mut all_bits = Vec::new();
    for mut c in s.chars() {
        // non ascii will stay unchanged, nice~
        c.make_ascii_uppercase();
        all_bits.extend_from_slice(*base32_map.get(&c).ok_or(ParseError::InvalidBase32Char(c))?);
    }

    let bytes = all_bits.chunks(8).map(|bits| {
        bits.iter().rev().enumerate().fold(0u8, |init, (index, bit)| {
            if *bit {
                // index is always in 0-7
                return init + 2u8.pow(index as u32)
            }
            init
        })
    }).collect();
    Ok(bytes)
}
