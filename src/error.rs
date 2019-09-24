use std::fmt::Formatter;
use std::error::Error;
use std::fmt;
use std::num::ParseIntError;


#[derive(Debug, Clone)]
pub enum ParseError {
    InvalidBase32Char,
    ToIntError(ParseIntError),

}

impl Error for ParseError {
    fn description (&self) -> &str {
        match self {
            ParseError::InvalidBase32Char => "Invalid base32 char, should be A-Z, 2-7",
            ParseError::ToIntError(ref e) =>  e.description(),
        }
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ParseError::InvalidBase32Char => None,
            ParseError::ToIntError(ref e) => Some(e),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidBase32Char => write!(f, "Invalid base32 char, should be A-Z, 2-7"),
            ParseError::ToIntError(ref e) => e.fmt(f),
        }
    }
}

impl From<ParseIntError> for ParseError {
    fn from(err: ParseIntError) -> ParseError {
        ParseError::ToIntError(err)
    } 
}
