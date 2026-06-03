//! Community (SNMPv1/v2c) client: GET, GETNEXT and WALK against a live agent.
//!
//! Run against any SNMP agent (defaults to a local agent on udp/161):
//! ```text
//! cargo run -p netsnmp-examples --example client -- 127.0.0.1:11611 public
//! ```
//! Start one first, e.g. `snmpd 127.0.0.1:11611`, or use the `loopback`
//! example if you don't have an agent handy.

use netsnmp::{Oid, Session, SessionConfig};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), netsnmp::Error> {
    netsnmp_examples::init_tracing();

    let mut args = std::env::args().skip(1);
    let agent = args.next().unwrap_or_else(|| "127.0.0.1:161".to_string());
    let community = args.next().unwrap_or_else(|| "public".to_string());

    // SessionConfig carries the version, community, timeout and retry policy.
    let config = SessionConfig {
        community: community.into_bytes(),
        ..SessionConfig::default() // v2c, 5s timeout, 2 retries
    };
    let session = Session::open_udp(&agent, config).await?;
    info!("connected to {agent}");

    // GET several scalars in a single request.
    let oids: Vec<Oid> = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]
        .iter()
        .map(|s| s.parse())
        .collect::<Result<_, _>>()?;
    match session.get(&oids).await {
        Ok(vars) => {
            for vb in vars {
                info!("GET  {} = {}", vb.oid, vb.value);
            }
        }
        Err(e) => error!("GET failed (is the agent running?): {e}"),
    }

    // GETNEXT: the lexicographic successor of an OID.
    let sys: Oid = "1.3.6.1.2.1.1".parse()?;
    if let Ok(vars) = session.get_next(std::slice::from_ref(&sys)).await {
        for vb in vars {
            info!("NEXT {} = {}", vb.oid, vb.value);
        }
    }

    // WALK the whole `system` subtree via repeated GETNEXT.
    info!("WALK system:");
    match session.walk(&sys).await {
        Ok(vars) => {
            for vb in vars {
                info!("       {} = {}", vb.oid, vb.value);
            }
        }
        Err(e) => error!("WALK failed: {e}"),
    }

    Ok(())
}
