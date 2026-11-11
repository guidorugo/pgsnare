// SPDX-License-Identifier: Apache-2.0

//! Assembles a proxy from its parts.
//!
//! A proxy is made of one protocol module, one login strategy and one or
//! more event sinks. The `pgsnare` binary assembles the parts that ship with
//! pgsnare. Another build can assemble its own, from the same crates:
//!
//! ```
//! use std::sync::Arc;
//!
//! use pgsnare::builder::{BuildError, ProxyBuilder};
//! use pgsnare_core::extension::Relay;
//!
//! // Without a protocol module and a sink there is no proxy.
//! let result = ProxyBuilder::new().login_strategy(Arc::new(Relay)).build();
//! assert_eq!(result.err(), Some(BuildError::NoProtocolModule));
//! ```
//!
//! The parts are compiled in. Nothing is loaded at run time: a part is a
//! value of a Rust type that implements one of the traits in
//! [`pgsnare_core::extension`].

use std::fmt;
use std::sync::Arc;

use pgsnare_core::extension::{EventSink, LoginStrategy, ProtocolModule, ProtocolSession};
use pgsnare_core::session::SessionOrigin;

/// Collects the parts of a proxy.
#[derive(Default)]
pub struct ProxyBuilder {
    protocol_modules: Vec<Arc<dyn ProtocolModule>>,
    login_strategies: Vec<Arc<dyn LoginStrategy>>,
    event_sinks: Vec<Arc<dyn EventSink>>,
}

impl ProxyBuilder {
    /// A builder with no parts.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the protocol module. A proxy has exactly one.
    #[must_use]
    pub fn protocol_module(mut self, module: Arc<dyn ProtocolModule>) -> Self {
        self.protocol_modules.push(module);
        self
    }

    /// Sets the login strategy. A proxy has exactly one.
    #[must_use]
    pub fn login_strategy(mut self, strategy: Arc<dyn LoginStrategy>) -> Self {
        self.login_strategies.push(strategy);
        self
    }

    /// Adds an event sink. A proxy has at least one.
    #[must_use]
    pub fn event_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.event_sinks.push(sink);
        self
    }

    /// Checks that the parts make a proxy and puts them together.
    ///
    /// # Errors
    ///
    /// Returns what is missing or given more than once. A proxy without a
    /// sink is refused, because it would detect and tell nobody.
    pub fn build(self) -> Result<Proxy, BuildError> {
        let Self {
            mut protocol_modules,
            mut login_strategies,
            event_sinks,
        } = self;

        let protocol_module = match (protocol_modules.pop(), protocol_modules.is_empty()) {
            (Some(module), true) => module,
            (Some(_), false) => return Err(BuildError::SeveralProtocolModules),
            (None, _) => return Err(BuildError::NoProtocolModule),
        };
        let login_strategy = match (login_strategies.pop(), login_strategies.is_empty()) {
            (Some(strategy), true) => strategy,
            (Some(_), false) => return Err(BuildError::SeveralLoginStrategies),
            (None, _) => return Err(BuildError::NoLoginStrategy),
        };
        if event_sinks.is_empty() {
            return Err(BuildError::NoEventSink);
        }

        Ok(Proxy {
            protocol_module,
            login_strategy,
            event_sinks,
        })
    }
}

impl fmt::Debug for ProxyBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyBuilder")
            .field(
                "protocol_modules",
                &names(&self.protocol_modules, |module| module.name()),
            )
            .field(
                "login_strategies",
                &names(&self.login_strategies, |strategy| strategy.name()),
            )
            .field("event_sinks", &names(&self.event_sinks, |sink| sink.name()))
            .finish()
    }
}

fn names<T: ?Sized>(parts: &[Arc<T>], name: impl Fn(&T) -> &str) -> Vec<&str> {
    parts.iter().map(|part| name(part)).collect()
}

/// Why the parts do not make a proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// No protocol module was given.
    NoProtocolModule,
    /// More than one protocol module was given.
    SeveralProtocolModules,
    /// No login strategy was given.
    NoLoginStrategy,
    /// More than one login strategy was given.
    SeveralLoginStrategies,
    /// No event sink was given.
    NoEventSink,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoProtocolModule => "a proxy needs a protocol module",
            Self::SeveralProtocolModules => "a proxy has exactly one protocol module",
            Self::NoLoginStrategy => "a proxy needs a login strategy",
            Self::SeveralLoginStrategies => "a proxy has exactly one login strategy",
            Self::NoEventSink => "a proxy needs at least one event sink",
        })
    }
}

impl std::error::Error for BuildError {}

/// The parts of a proxy, put together.
///
/// The runtime that accepts connections and drives the sessions is built on
/// top of this.
#[derive(Clone)]
pub struct Proxy {
    protocol_module: Arc<dyn ProtocolModule>,
    login_strategy: Arc<dyn LoginStrategy>,
    event_sinks: Vec<Arc<dyn EventSink>>,
}

impl Proxy {
    /// The protocol module.
    #[must_use]
    pub fn protocol_module(&self) -> &Arc<dyn ProtocolModule> {
        &self.protocol_module
    }

    /// The login strategy.
    #[must_use]
    pub fn login_strategy(&self) -> &Arc<dyn LoginStrategy> {
        &self.login_strategy
    }

    /// The event sinks, in the order they were added.
    #[must_use]
    pub fn event_sinks(&self) -> &[Arc<dyn EventSink>] {
        &self.event_sinks
    }

    /// Creates the logic for one accepted connection: a session of the
    /// protocol module that logs in with the login strategy.
    #[must_use]
    pub fn start_session(&self, origin: SessionOrigin) -> Box<dyn ProtocolSession> {
        self.protocol_module
            .start_session(origin, Arc::clone(&self.login_strategy))
    }
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("protocol_module", &self.protocol_module.name())
            .field("login_strategy", &self.login_strategy.name())
            .field("event_sinks", &names(&self.event_sinks, |sink| sink.name()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    use pgsnare_core::event::{Event, SessionId};
    use pgsnare_core::extension::{
        LoginDecision, LoginError, LoginExchange, Relay, SessionError, SinkError, SinkFuture,
    };
    use pgsnare_core::policy::PolicySnapshot;
    use pgsnare_core::session::{Direction, Output};

    use super::*;

    /// A protocol whose login is one message in each direction. It asks the
    /// login strategy what to do with each and records which strategy it
    /// was given.
    struct TestProtocol;

    struct TestSession {
        login: Box<dyn LoginExchange>,
        login_name: &'static str,
    }

    impl ProtocolModule for TestProtocol {
        fn name(&self) -> &'static str {
            "test-protocol"
        }

        fn start_session(
            &self,
            origin: SessionOrigin,
            login: Arc<dyn LoginStrategy>,
        ) -> Box<dyn ProtocolSession> {
            Box::new(TestSession {
                login: login.begin(&origin),
                login_name: login.name(),
            })
        }
    }

    impl ProtocolSession for TestSession {
        fn on_bytes(
            &mut self,
            from: Direction,
            input: &[u8],
            _policy: &PolicySnapshot,
            out: &mut Output,
        ) -> Result<(), SessionError> {
            let decision = self
                .login
                .on_message(from, input)
                .map_err(|_| SessionError::new("the login strategy refused the message"))?;
            let (to_client, to_server) = match decision {
                LoginDecision::Forward => match from {
                    Direction::FromClient => (Vec::new(), input.to_vec()),
                    Direction::FromServer => (input.to_vec(), Vec::new()),
                },
                LoginDecision::Replace {
                    to_client,
                    to_server,
                } => (to_client, to_server),
                _ => return Err(SessionError::new("a decision this test does not know")),
            };
            out.to_client.extend_from_slice(&to_client);
            out.to_client.extend_from_slice(self.login_name.as_bytes());
            out.to_server.extend_from_slice(&to_server);
            Ok(())
        }
    }

    /// A login strategy of another build: it answers the client itself.
    struct Terminate;

    struct TerminateExchange;

    impl LoginStrategy for Terminate {
        fn name(&self) -> &'static str {
            "terminate"
        }

        fn begin(&self, _origin: &SessionOrigin) -> Box<dyn LoginExchange> {
            Box::new(TerminateExchange)
        }
    }

    impl LoginExchange for TerminateExchange {
        fn on_message(
            &mut self,
            from: Direction,
            message: &[u8],
        ) -> Result<LoginDecision, LoginError> {
            match from {
                Direction::FromClient if message == b"bad" => {
                    Err(LoginError::new("the client sent a bad message"))
                }
                Direction::FromClient => Ok(LoginDecision::Replace {
                    to_client: b"challenge:".to_vec(),
                    to_server: Vec::new(),
                }),
                Direction::FromServer => Ok(LoginDecision::Forward),
            }
        }
    }

    #[derive(Default)]
    struct MemorySink {
        name: String,
        delivered: Mutex<Vec<Event>>,
    }

    impl MemorySink {
        fn named(name: &str) -> Self {
            Self {
                name: name.to_owned(),
                delivered: Mutex::default(),
            }
        }
    }

    impl EventSink for MemorySink {
        fn name(&self) -> &str {
            &self.name
        }

        fn deliver<'a>(&'a self, event: &'a Event) -> SinkFuture<'a> {
            Box::pin(async move {
                self.delivered
                    .lock()
                    .map_err(|_| SinkError::permanent("the sink is poisoned"))?
                    .push(event.clone());
                Ok(())
            })
        }
    }

    fn origin() -> SessionOrigin {
        SessionOrigin::new(
            SessionId::from_u128(1),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            49_152,
            false,
        )
    }

    #[test]
    fn a_proxy_is_assembled_from_the_shipped_parts() {
        let proxy = ProxyBuilder::new()
            .protocol_module(Arc::new(TestProtocol))
            .login_strategy(Arc::new(Relay))
            .event_sink(Arc::new(MemorySink::named("first")))
            .event_sink(Arc::new(MemorySink::named("second")))
            .build()
            .unwrap();

        assert_eq!(proxy.protocol_module().name(), "test-protocol");
        assert_eq!(proxy.login_strategy().name(), "relay");
        let sinks: Vec<&str> = proxy.event_sinks().iter().map(|sink| sink.name()).collect();
        assert_eq!(sinks, ["first", "second"]);
        assert_eq!(
            format!("{proxy:?}"),
            "Proxy { protocol_module: \"test-protocol\", login_strategy: \"relay\", \
             event_sinks: [\"first\", \"second\"] }"
        );

        // The session the proxy starts uses the proxy's login strategy.
        let policy = PolicySnapshot::builder().build().unwrap();
        let mut session = proxy.start_session(origin());
        let mut out = Output::new();
        session
            .on_bytes(Direction::FromClient, b"hello", &policy, &mut out)
            .unwrap();
        assert_eq!(out.to_server, b"hello");
        assert_eq!(out.to_client, b"relay");
    }

    #[test]
    fn another_build_can_supply_its_own_parts() {
        let proxy = ProxyBuilder::new()
            .login_strategy(Arc::new(Terminate))
            .event_sink(Arc::new(MemorySink::named("only")))
            .protocol_module(Arc::new(TestProtocol))
            .build()
            .unwrap();
        assert_eq!(proxy.login_strategy().name(), "terminate");

        let policy = PolicySnapshot::builder().build().unwrap();
        let mut session = proxy.start_session(origin());
        let mut out = Output::new();
        session
            .on_bytes(Direction::FromClient, b"hello", &policy, &mut out)
            .unwrap();
        // The strategy answered the client and sent nothing to the server.
        assert_eq!(out.to_client, b"challenge:terminate");
        assert!(out.to_server.is_empty());

        let error = session
            .on_bytes(Direction::FromClient, b"bad", &policy, &mut out)
            .unwrap_err();
        assert_eq!(error.reason(), "the login strategy refused the message");
    }

    #[test]
    fn a_proxy_needs_exactly_one_protocol_and_one_login_strategy_and_a_sink() {
        let sink = || -> Arc<dyn EventSink> { Arc::new(MemorySink::named("sink")) };
        let build = |builder: ProxyBuilder| builder.build().map(|_| ()).unwrap_err();

        assert_eq!(build(ProxyBuilder::new()), BuildError::NoProtocolModule);
        assert_eq!(
            build(ProxyBuilder::new().protocol_module(Arc::new(TestProtocol))),
            BuildError::NoLoginStrategy
        );
        assert_eq!(
            build(
                ProxyBuilder::new()
                    .protocol_module(Arc::new(TestProtocol))
                    .login_strategy(Arc::new(Relay))
            ),
            BuildError::NoEventSink
        );
        assert_eq!(
            build(
                ProxyBuilder::new()
                    .protocol_module(Arc::new(TestProtocol))
                    .protocol_module(Arc::new(TestProtocol))
                    .login_strategy(Arc::new(Relay))
                    .event_sink(sink())
            ),
            BuildError::SeveralProtocolModules
        );
        assert_eq!(
            build(
                ProxyBuilder::new()
                    .protocol_module(Arc::new(TestProtocol))
                    .login_strategy(Arc::new(Relay))
                    .login_strategy(Arc::new(Terminate))
                    .event_sink(sink())
            ),
            BuildError::SeveralLoginStrategies
        );
        assert_eq!(
            BuildError::NoEventSink.to_string(),
            "a proxy needs at least one event sink"
        );
    }

    #[test]
    fn the_builder_shows_its_parts_by_name() {
        let builder = ProxyBuilder::new()
            .login_strategy(Arc::new(Relay))
            .event_sink(Arc::new(MemorySink::named("stdout")));
        assert_eq!(
            format!("{builder:?}"),
            "ProxyBuilder { protocol_modules: [], login_strategies: [\"relay\"], \
             event_sinks: [\"stdout\"] }"
        );
    }

    #[test]
    fn a_proxy_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Proxy>();
        assert_send_sync::<ProxyBuilder>();
    }
}
