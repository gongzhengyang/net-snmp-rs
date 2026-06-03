//! SNMPv3 / USM client (authentication + privacy).
//!
//! `V3Session::open_udp` performs RFC 3414 engine discovery and time
//! synchronization automatically, then every request is HMAC-authenticated and
//! AES-encrypted.
//!
//! Run (args: agent, user, authPass, privPass):
//! ```text
//! cargo run -p netsnmp-examples --example v3_client -- \
//!     127.0.0.1:11611 myuser authpassword privpassword
//! ```
//! The agent must know this user, e.g.:
//! `snmpd -u myuser -a SHA -A authpassword -x AES -X privpassword 127.0.0.1:11611`

use std::time::Duration;

use netsnmp::{AuthProtocol, Oid, PrivProtocol, UsmUser, V3Session};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), netsnmp::Error> {
    netsnmp_examples::init_tracing();

    let mut args = std::env::args().skip(1);
    let agent = args.next().unwrap_or_else(|| "127.0.0.1:11611".to_string());
    let user_name = args.next().unwrap_or_else(|| "myuser".to_string());
    let auth_pass = args.next().unwrap_or_else(|| "authpassword".to_string());
    let priv_pass = args.next().unwrap_or_else(|| "privpassword".to_string());

    // Build the USM credentials. `auth_priv` = authPriv security level;
    // there are also `UsmUser::auth` (authNoPriv) and `UsmUser::noauth`.
    let user = UsmUser::auth_priv(
        &user_name,
        AuthProtocol::HmacSha1,
        &auth_pass,
        PrivProtocol::AesCfb128,
        &priv_pass,
    );

    // open_udp discovers the engine (engineID/boots/time) before returning.
    let mut session = V3Session::open_udp(&agent, user, Duration::from_secs(5), 2).await?;

    info!("discovered engineID = {}", session.engine().engine_id_hex());

    let sys_descr: Oid = "1.3.6.1.2.1.1.1.0".parse()?;
    info!("GET sysDescr.0 = {}", session.get_one(&sys_descr).await?);

    Ok(())
}
