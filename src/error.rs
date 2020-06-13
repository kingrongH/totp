use thiserror::Error;


#[derive(Error, Debug)]
pub enum ParseError {
    #[error("invalid base32 char `{0}`, base32 char should be in A-Z or 2-7")]
    InvalidBase32Char(char),
}

