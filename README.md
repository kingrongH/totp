
`TOTP` project is used for calculate a [Time-based One-time Password](https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm)
For more infomation, please check the link above

## Quick Start

```shell
git clone https://github.com/kingrongH/totp
cd totp
```

```shell
cargo run XW7HPZJ2L3AMPWQN
```

## Example

```rust
use totp::*;

fn main() -> Result<(), Box<dyn std::error::Error>>{
    let x = "XW7HPZJ2L3AMPWQN";
    let key = base32_to_secret(&x)?;
    let totp = TOTP::default(&key);
    let code = totp.get_code()?;
    let left_time = totp.get_left_time();
    println!("code: {:06}\r\nleft time: {}s", code, left_time);
    Ok(())
}
```

## Update

* 2019.9.29: Change the secret type to &[u8]

## LICENSE

under MIT LICENSE
