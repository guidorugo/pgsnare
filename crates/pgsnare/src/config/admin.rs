// SPDX-License-Identifier: Apache-2.0

//! The admin and metrics listeners, and shutdown.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::Deserialize;

use super::error::{At, Problems};
use super::names::ListenAddr;
use super::units;

/// The default port of the admin listener.
pub const DEFAULT_ADMIN_PORT: u16 = 9641;

/// The default port of the metrics listener.
pub const DEFAULT_METRICS_PORT: u16 = 9642;

const fn loopback(port: u16) -> ListenAddr {
    ListenAddr::new(SocketAddr::new(
        std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
    ))
}

/// The admin listener, which serves the health endpoints.
///
/// It is read-only and bound to loopback by default. `pgsnare healthcheck`
/// asks it, so no health port has to be reachable from outside.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct Admin {
    /// The address to listen on. The default is `127.0.0.1:9641`.
    pub listen: ListenAddr,
}

impl Default for Admin {
    fn default() -> Self {
        Self {
            listen: loopback(DEFAULT_ADMIN_PORT),
        }
    }
}

/// The metrics listener, which serves metrics in Prometheus format.
///
/// It is read-only and bound to loopback by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct Metrics {
    /// The address to listen on. The default is `127.0.0.1:9642`.
    pub listen: ListenAddr,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            listen: loopback(DEFAULT_METRICS_PORT),
        }
    }
}

/// How pgsnare stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct Shutdown {
    /// How long open sessions get to finish after a request to stop. The
    /// rest are then closed. The default is 25 seconds, a little less than
    /// the 30 seconds Kubernetes waits before it kills a pod.
    #[serde(deserialize_with = "units::duration")]
    pub grace_period: Duration,
}

/// The default for [`Shutdown::grace_period`].
pub const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(25);

/// The longest accepted [`Shutdown::grace_period`]: one hour.
pub const MAX_GRACE_PERIOD: Duration = Duration::from_secs(3600);

impl Default for Shutdown {
    fn default() -> Self {
        Self {
            grace_period: DEFAULT_GRACE_PERIOD,
        }
    }
}

impl Shutdown {
    pub(super) fn validate(&self, at: &At, problems: &mut Problems) {
        if self.grace_period > MAX_GRACE_PERIOD {
            problems.add(&at.field("grace_period"), "must be at most 1h");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::yaml;
    use super::*;

    #[test]
    fn both_listeners_default_to_loopback() {
        let admin: Admin = yaml::from_str("{}\n").unwrap();
        assert_eq!(admin, Admin::default());
        assert_eq!(admin.listen.to_string(), "127.0.0.1:9641");
        assert!(admin.listen.is_loopback());

        let metrics: Metrics = yaml::from_str("{}\n").unwrap();
        assert_eq!(metrics, Metrics::default());
        assert_eq!(metrics.listen.to_string(), "127.0.0.1:9642");
        assert!(metrics.listen.is_loopback());
    }

    #[test]
    fn the_addresses_can_be_set() {
        let admin: Admin = yaml::from_str("listen: 127.0.0.1:19641\n").unwrap();
        assert_eq!(admin.listen.to_string(), "127.0.0.1:19641");
        let metrics: Metrics = yaml::from_str("listen: 0.0.0.0:9642\n").unwrap();
        assert!(!metrics.listen.is_loopback());

        assert!(yaml::from_str::<Admin>("listen: localhost:9641\n").is_err());
        assert!(yaml::from_str::<Admin>("listen: 9641\n").is_err());
        assert!(yaml::from_str::<Admin>("port: 9641\n").is_err());
        assert!(yaml::from_str::<Metrics>("listen: 127.0.0.1:9642\npath: /metrics\n").is_err());
    }

    #[test]
    fn the_grace_period_is_bounded() {
        let problems = |text: &str| {
            let shutdown: Shutdown = yaml::from_str(text).unwrap();
            let mut problems = Problems::new();
            shutdown.validate(&At::root().field("shutdown"), &mut problems);
            problems.into_result().map_err(|error| error.to_string())
        };
        assert_eq!(Shutdown::default().grace_period, Duration::from_secs(25));
        assert!(problems("{}\n").is_ok());
        assert!(problems("grace_period: 0s\n").is_ok());
        assert!(problems("grace_period: 1h\n").is_ok());
        assert_eq!(
            problems("grace_period: 61m\n").unwrap_err(),
            "shutdown.grace_period: must be at most 1h"
        );
        assert!(yaml::from_str::<Shutdown>("grace_period: 25\n").is_err());
    }
}
