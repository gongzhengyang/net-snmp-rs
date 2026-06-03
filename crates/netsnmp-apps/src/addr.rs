//! Address normalization helpers for agents and listen addresses.

use netsnmp::transport::UdpTransport;

/// Normalize an agent string into `host:port`, defaulting the SNMP agent port
/// (161) and stripping an optional `udp:` transport prefix.
pub fn normalize_agent(agent: &str) -> String {
    normalize_agent_port(agent, UdpTransport::DEFAULT_PORT)
}

/// Like [`normalize_agent`], but uses `default_port` when the address carries
/// no explicit port (e.g. 162 for notification receivers).
pub fn normalize_agent_port(agent: &str, default_port: u16) -> String {
    let agent = agent.strip_prefix("udp:").unwrap_or(agent);
    // Bare IPv6 literals in brackets, or host already containing a port.
    if agent.starts_with('[') {
        if agent.contains("]:") {
            return agent.to_string();
        }
        return format!("{agent}:{default_port}");
    }
    if agent.matches(':').count() == 1 {
        agent.to_string()
    } else if agent.contains(':') {
        // Raw IPv6 without brackets: wrap it.
        format!("[{agent}]:{default_port}")
    } else {
        format!("{agent}:{default_port}")
    }
}

/// Normalize an `agentAddress` specification (e.g. `udp:161`,
/// `udp:127.0.0.1:1161`, or a bare port) into a bindable `host:port` string.
pub fn normalize_bind_addr(spec: &str) -> String {
    let spec = spec.split(',').next().unwrap_or(spec).trim();
    let spec = spec
        .strip_prefix("udp:")
        .or_else(|| spec.strip_prefix("tcp:"))
        .unwrap_or(spec);
    if !spec.is_empty() && spec.chars().all(|c| c.is_ascii_digit()) {
        return format!("0.0.0.0:{spec}");
    }
    if spec.starts_with('[') {
        if spec.contains("]:") {
            return spec.to_string();
        }
        return format!("{spec}:{}", UdpTransport::DEFAULT_PORT);
    }
    if spec.matches(':').count() == 1 {
        spec.to_string()
    } else if spec.contains(':') {
        format!("[{spec}]:{}", UdpTransport::DEFAULT_PORT)
    } else {
        format!("{spec}:{}", UdpTransport::DEFAULT_PORT)
    }
}
