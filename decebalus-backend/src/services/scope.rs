//! Scope-lock: refuse to touch anything outside the active engagement's declared
//! CIDRs. Enforced centrally in the job executor before any targeted job runs, so
//! an operator can never accidentally point a module at an out-of-scope host.
//!
//! Policy: scope-lock only engages when there is an active engagement *and* it
//! declares at least one parseable CIDR. With no engagement (or an empty scope)
//! the tool is permissive, preserving the original home-network behavior.

use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use crate::db::repository;
use crate::state::AppState;

/// True if `target` (an IP, a CIDR, or "self") is allowed by the active scope.
pub async fn target_in_scope(state: &Arc<AppState>, target: &str) -> bool {
    let Some(engagement) = repository::get_active_engagement(&state.db).await.ok().flatten() else {
        return true; // no engagement → permissive
    };
    let scopes: Vec<IpNet> = engagement
        .scope_cidrs
        .iter()
        .filter_map(|c| c.parse::<IpNet>().ok())
        .collect();
    in_scope(&scopes, target)
}

/// Pure scope check against a set of CIDRs. Empty scope ⇒ permissive; "self" ⇒
/// allowed; an IP or CIDR must be contained by some scope; anything else is refused.
pub fn in_scope(scopes: &[IpNet], target: &str) -> bool {
    if scopes.is_empty() {
        return true;
    }
    if target == "self" {
        return true;
    }
    if let Ok(ip) = target.parse::<IpAddr>() {
        return scopes.iter().any(|s| s.contains(&ip));
    }
    if let Ok(net) = target.parse::<IpNet>() {
        return scopes.iter().any(|s| s.contains(&net));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(cidrs: &[&str]) -> Vec<IpNet> {
        cidrs.iter().map(|c| c.parse().unwrap()).collect()
    }

    #[test]
    fn empty_scope_is_permissive() {
        assert!(in_scope(&[], "8.8.8.8"));
    }

    #[test]
    fn enforces_ip_and_cidr_membership() {
        let s = nets(&["10.0.0.0/24", "192.168.1.0/24"]);
        assert!(in_scope(&s, "self"));
        assert!(in_scope(&s, "10.0.0.5"));
        assert!(in_scope(&s, "192.168.1.20"));
        assert!(in_scope(&s, "10.0.0.0/25")); // subnet of scope
        assert!(!in_scope(&s, "10.0.1.5")); // outside
        assert!(!in_scope(&s, "8.8.8.8"));
        assert!(!in_scope(&s, "10.0.0.0/16")); // wider than scope
        assert!(!in_scope(&s, "not-an-ip"));
    }
}
