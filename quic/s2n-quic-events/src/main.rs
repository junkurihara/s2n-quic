// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T, E = Error> = core::result::Result<T, E>;

mod parser;

#[derive(Debug, Default)]
enum OutputMode {
    Ref,
    #[default]
    Mut,
}

impl OutputMode {
    fn receiver(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(),
            OutputMode::Mut => quote!(mut),
        }
    }
    fn counter_type(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(AtomicU32),
            OutputMode::Mut => quote!(u32),
        }
    }

    fn counter_init(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(AtomicU32::new(0)),
            OutputMode::Mut => quote!(0),
        }
    }

    fn counter_increment(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(.fetch_add(1, Ordering::Relaxed)),
            OutputMode::Mut => quote!(+= 1),
        }
    }

    fn counter_load(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(.load(Ordering::Relaxed)),
            OutputMode::Mut => quote!(),
        }
    }

    fn lock(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(.lock().unwrap()),
            OutputMode::Mut => quote!(),
        }
    }

    fn imports(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(
                use core::sync::atomic::{AtomicU32, Ordering};
            ),
            OutputMode::Mut => quote!(),
        }
    }

    fn mutex(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(
                use std::sync::Mutex;
            ),
            OutputMode::Mut => quote!(),
        }
    }

    fn testing_output_type(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(Mutex<Vec<String>>),
            OutputMode::Mut => quote!(Vec<String>),
        }
    }

    fn target_crate(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!("s2n_quic_dc"),
            OutputMode::Mut => quote!("s2n_quic"),
        }
    }

    fn trait_constraints(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!('static + Send + Sync),
            OutputMode::Mut => quote!('static + Send),
        }
    }

    fn query_mut(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(),
            OutputMode::Mut => quote!(
                /// Used for querying and mutating the `Subscriber::ConnectionContext` on a Subscriber
                #[inline]
                fn query_mut(
                    context: &mut Self::ConnectionContext,
                    query: &mut dyn query::QueryMut,
                ) -> query::ControlFlow {
                    query.execute_mut(context)
                }
            ),
        }
    }

    fn query_mut_tuple(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(),
            OutputMode::Mut => quote!(
                #[inline]
                fn query_mut(
                    context: &mut Self::ConnectionContext,
                    query: &mut dyn query::QueryMut,
                ) -> query::ControlFlow {
                    query
                        .execute_mut(context)
                        .and_then(|| A::query_mut(&mut context.0, query))
                        .and_then(|| B::query_mut(&mut context.1, query))
                }
            ),
        }
    }

    fn supervisor(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(),
            OutputMode::Mut => quote!(
                pub mod supervisor {
                    //! This module contains the `supervisor::Outcome` and `supervisor::Context` for use
                    //! when implementing [`Subscriber::supervisor_timeout`](crate::event::Subscriber::supervisor_timeout) and
                    //! [`Subscriber::on_supervisor_timeout`](crate::event::Subscriber::on_supervisor_timeout)
                    //! on a Subscriber.

                    use crate::{
                        application,
                        event::{builder::SocketAddress, IntoEvent},
                    };

                    #[non_exhaustive]
                    #[derive(Clone, Debug, Eq, PartialEq)]
                    pub enum Outcome {
                        /// Allow the connection to remain open
                        Continue,

                        /// Close the connection and notify the peer
                        Close { error_code: application::Error },

                        /// Close the connection without notifying the peer
                        ImmediateClose { reason: &'static str },
                    }

                    impl Default for Outcome {
                        fn default() -> Self {
                            Self::Continue
                        }
                    }

                    #[non_exhaustive]
                    #[derive(Debug)]
                    pub struct Context<'a> {
                        /// Number of handshakes that have begun but not completed
                        pub inflight_handshakes: usize,

                        /// Number of open connections
                        pub connection_count: usize,

                        /// The address of the peer
                        pub remote_address: SocketAddress<'a>,

                        /// True if the connection is in the handshake state, false otherwise
                        pub is_handshaking: bool,
                    }

                    impl<'a> Context<'a> {
                        pub fn new(
                            inflight_handshakes: usize,
                            connection_count: usize,
                            remote_address: &'a crate::inet::SocketAddress,
                            is_handshaking: bool,
                        ) -> Self {
                            Self {
                                inflight_handshakes,
                                connection_count,
                                remote_address: remote_address.into_event(),
                                is_handshaking,
                            }
                        }
                    }
                }
            ),
        }
    }

    fn supervisor_timeout(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(),
            OutputMode::Mut => quote!(
                /// The period at which `on_supervisor_timeout` is called
                ///
                /// If multiple `event::Subscriber`s are composed together, the minimum `supervisor_timeout`
                /// across all `event::Subscriber`s will be used.
                ///
                /// If the `supervisor_timeout()` is `None` across all `event::Subscriber`s, connection supervision
                /// will cease for the remaining lifetime of the connection and `on_supervisor_timeout` will no longer
                /// be called.
                ///
                /// It is recommended to avoid setting this value less than ~100ms, as short durations
                /// may lead to higher CPU utilization.
                #[allow(unused_variables)]
                fn supervisor_timeout(
                    &mut self,
                    conn_context: &mut Self::ConnectionContext,
                    meta: &api::ConnectionMeta,
                    context: &supervisor::Context,
                ) -> Option<Duration> {
                    None
                }

                /// Called for each `supervisor_timeout` to determine any action to take on the connection based on the `supervisor::Outcome`
                ///
                /// If multiple `event::Subscriber`s are composed together, the minimum `supervisor_timeout`
                /// across all `event::Subscriber`s will be used, and thus `on_supervisor_timeout` may be called
                /// earlier than the `supervisor_timeout` for a given `event::Subscriber` implementation.
                #[allow(unused_variables)]
                fn on_supervisor_timeout(
                    &mut self,
                    conn_context: &mut Self::ConnectionContext,
                    meta: &api::ConnectionMeta,
                    context: &supervisor::Context,
                ) -> supervisor::Outcome {
                    supervisor::Outcome::default()
                }
            ),
        }
    }

    fn supervisor_timeout_tuple(&self) -> TokenStream {
        match self {
            OutputMode::Ref => quote!(),
            OutputMode::Mut => quote!(
                #[inline]
                fn supervisor_timeout(
                    &mut self,
                    conn_context: &mut Self::ConnectionContext,
                    meta: &api::ConnectionMeta,
                    context: &supervisor::Context,
                ) -> Option<Duration> {
                    let timeout_a = self
                        .0
                        .supervisor_timeout(&mut conn_context.0, meta, context);
                    let timeout_b = self
                        .1
                        .supervisor_timeout(&mut conn_context.1, meta, context);
                    match (timeout_a, timeout_b) {
                        (None, None) => None,
                        (None, Some(timeout)) | (Some(timeout), None) => Some(timeout),
                        (Some(a), Some(b)) => Some(a.min(b)),
                    }
                }

                #[inline]
                fn on_supervisor_timeout(
                    &mut self,
                    conn_context: &mut Self::ConnectionContext,
                    meta: &api::ConnectionMeta,
                    context: &supervisor::Context,
                ) -> supervisor::Outcome {
                    let outcome_a =
                        self.0
                            .on_supervisor_timeout(&mut conn_context.0, meta, context);
                    let outcome_b =
                        self.1
                            .on_supervisor_timeout(&mut conn_context.1, meta, context);
                    match (outcome_a, outcome_b) {
                        (supervisor::Outcome::ImmediateClose { reason }, _)
                        | (_, supervisor::Outcome::ImmediateClose { reason }) => {
                            supervisor::Outcome::ImmediateClose { reason }
                        }
                        (supervisor::Outcome::Close { error_code }, _)
                        | (_, supervisor::Outcome::Close { error_code }) => {
                            supervisor::Outcome::Close { error_code }
                        }
                        _ => supervisor::Outcome::Continue,
                    }
                }
            ),
        }
    }
}

impl ToTokens for OutputMode {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(self.receiver());
    }
}

#[derive(Debug, Default)]
struct Output {
    pub subscriber: TokenStream,
    pub endpoint_publisher: TokenStream,
    pub endpoint_publisher_subscriber: TokenStream,
    pub connection_publisher: TokenStream,
    pub connection_publisher_subscriber: TokenStream,
    pub tuple_subscriber: TokenStream,
    pub tracing_subscriber: TokenStream,
    pub tracing_subscriber_attr: TokenStream,
    pub tracing_subscriber_def: TokenStream,
    pub builders: TokenStream,
    pub api: TokenStream,
    pub testing_fields: TokenStream,
    pub testing_fields_init: TokenStream,
    pub subscriber_testing: TokenStream,
    pub endpoint_subscriber_testing: TokenStream,
    pub endpoint_testing_fields: TokenStream,
    pub endpoint_testing_fields_init: TokenStream,
    pub endpoint_publisher_testing: TokenStream,
    pub connection_publisher_testing: TokenStream,
    pub metrics_fields: TokenStream,
    pub metrics_fields_init: TokenStream,
    pub metrics_record: TokenStream,
    pub subscriber_metrics: TokenStream,
    pub extra: TokenStream,
    pub mode: OutputMode,
    pub s2n_quic_core_path: TokenStream,
}

impl ToTokens for Output {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Output {
            subscriber,
            endpoint_publisher,
            endpoint_publisher_subscriber,
            connection_publisher,
            connection_publisher_subscriber,
            tuple_subscriber,
            tracing_subscriber,
            tracing_subscriber_attr,
            tracing_subscriber_def,
            builders,
            api,
            testing_fields,
            testing_fields_init,
            subscriber_testing,
            endpoint_subscriber_testing,
            endpoint_testing_fields,
            endpoint_testing_fields_init,
            endpoint_publisher_testing,
            connection_publisher_testing,
            metrics_fields,
            metrics_fields_init,
            metrics_record,
            subscriber_metrics,
            extra,
            mode,
            s2n_quic_core_path,
        } = self;

        let imports = self.mode.imports();
        let mutex = self.mode.mutex();
        let testing_output_type = self.mode.testing_output_type();
        let lock = self.mode.lock();
        let target_crate = self.mode.target_crate();
        let supervisor = self.mode.supervisor();
        let supervisor_timeout = self.mode.supervisor_timeout();
        let supervisor_timeout_tuple = self.mode.supervisor_timeout_tuple();
        let query_mut = self.mode.query_mut();
        let query_mut_tuple = self.mode.query_mut_tuple();
        let trait_constraints = self.mode.trait_constraints();

        tokens.extend(quote!(
            use super::*;

            pub mod api {
                //! This module contains events that are emitted to the [`Subscriber`](crate::event::Subscriber)
                use super::*;

                pub use traits::Subscriber;

                #api

                #extra
            }

            #tracing_subscriber_attr
            pub mod tracing {
                //! This module contains event integration with [`tracing`](https://docs.rs/tracing)
                use super::api;

                #tracing_subscriber_def

                impl super::Subscriber for Subscriber {
                    type ConnectionContext = tracing::Span;

                    fn create_connection_context(
                        &#mode self,
                        meta: &api::ConnectionMeta,
                        _info: &api::ConnectionInfo
                    ) -> Self::ConnectionContext {
                        let parent = self.parent(meta);
                        tracing::span!(target: #target_crate, parent: parent, tracing::Level::DEBUG, "conn", id = meta.id)
                    }

                    #tracing_subscriber
                }
            }

            pub mod builder {
                use super::*;

                #builders
            }

            #supervisor

            pub use traits::*;
            mod traits {
                use super::*;
                use core::fmt;
                use #s2n_quic_core_path::query;
                use crate::event::Meta;

                /// Allows for events to be subscribed to
                pub trait Subscriber: #trait_constraints {

                    /// An application provided type associated with each connection.
                    ///
                    /// The context provides a mechanism for applications to provide a custom type
                    /// and update it on each event, e.g. computing statistics. Each event
                    /// invocation (e.g. [`Subscriber::on_packet_sent`]) also provides mutable
                    /// access to the context `&mut ConnectionContext` and allows for updating the
                    /// context.
                    ///
                    /// ```no_run
                    /// # mod s2n_quic { pub mod provider { pub mod event {
                    /// #     pub use s2n_quic_core::event::{api as events, api::ConnectionInfo, api::ConnectionMeta, Subscriber};
                    /// # }}}
                    /// use s2n_quic::provider::event::{
                    ///     ConnectionInfo, ConnectionMeta, Subscriber, events::PacketSent
                    /// };
                    ///
                    /// pub struct MyEventSubscriber;
                    ///
                    /// pub struct MyEventContext {
                    ///     packet_sent: u64,
                    /// }
                    ///
                    /// impl Subscriber for MyEventSubscriber {
                    ///     type ConnectionContext = MyEventContext;
                    ///
                    ///     fn create_connection_context(
                    ///         &mut self, _meta: &ConnectionMeta,
                    ///         _info: &ConnectionInfo,
                    ///     ) -> Self::ConnectionContext {
                    ///         MyEventContext { packet_sent: 0 }
                    ///     }
                    ///
                    ///     fn on_packet_sent(
                    ///         &mut self,
                    ///         context: &mut Self::ConnectionContext,
                    ///         _meta: &ConnectionMeta,
                    ///         _event: &PacketSent,
                    ///     ) {
                    ///         context.packet_sent += 1;
                    ///     }
                    /// }
                    ///  ```
                    type ConnectionContext: 'static + Send;

                    /// Creates a context to be passed to each connection-related event
                    fn create_connection_context(
                        &#mode self,
                        meta: &api::ConnectionMeta,
                        info: &api::ConnectionInfo
                    ) -> Self::ConnectionContext;

                    #supervisor_timeout

                    #subscriber

                    /// Called for each event that relates to the endpoint and all connections
                    #[inline]
                    fn on_event<M: Meta, E: Event>(&#mode self, meta: &M, event: &E) {
                        let _ = meta;
                        let _ = event;
                    }

                    /// Called for each event that relates to a connection
                    #[inline]
                    fn on_connection_event<E: Event>(
                        &#mode self,
                        context: &#mode Self::ConnectionContext,
                        meta: &api::ConnectionMeta,
                        event: &E
                    ) {
                        let _ = context;
                        let _ = meta;
                        let _ = event;
                    }

                    /// Used for querying the `Subscriber::ConnectionContext` on a Subscriber
                    #[inline]
                    fn query(context: &Self::ConnectionContext, query: &mut dyn query::Query) -> query::ControlFlow {
                        query.execute(context)
                    }

                    #query_mut
                }

                /// Subscriber is implemented for a 2-element tuple to make it easy to compose multiple
                /// subscribers.
                impl<A, B> Subscriber for (A, B)
                    where
                        A: Subscriber,
                        B: Subscriber,
                {
                    type ConnectionContext = (A::ConnectionContext, B::ConnectionContext);

                    #[inline]
                    fn create_connection_context(
                        &#mode self,
                        meta: &api::ConnectionMeta,
                        info: &api::ConnectionInfo
                    ) -> Self::ConnectionContext {
                        (self.0.create_connection_context(meta, info), self.1.create_connection_context(meta, info))
                    }

                    #supervisor_timeout_tuple

                    #tuple_subscriber

                    #[inline]
                    fn on_event<M: Meta, E: Event>(&#mode self, meta: &M, event: &E) {
                        self.0.on_event(meta, event);
                        self.1.on_event(meta, event);
                    }

                    #[inline]
                    fn on_connection_event<E: Event>(
                        &#mode self,
                        context: &#mode Self::ConnectionContext,
                        meta: &api::ConnectionMeta,
                        event: &E
                    ) {
                        self.0.on_connection_event(&#mode context.0, meta, event);
                        self.1.on_connection_event(&#mode context.1, meta, event);
                    }

                    #[inline]
                    fn query(context: &Self::ConnectionContext, query: &mut dyn query::Query) -> query::ControlFlow {
                        query.execute(context)
                            .and_then(|| A::query(&context.0, query))
                            .and_then(|| B::query(&context.1, query))
                    }

                    #query_mut_tuple
                }

                pub trait EndpointPublisher {
                    #endpoint_publisher

                    /// Returns the QUIC version, if any
                    fn quic_version(&self) -> Option<u32>;
                }

                pub struct EndpointPublisherSubscriber<'a, Sub: Subscriber> {
                    meta: api::EndpointMeta,
                    quic_version: Option<u32>,
                    subscriber: &'a #mode Sub,
                }

                impl<'a, Sub: Subscriber> fmt::Debug for EndpointPublisherSubscriber<'a, Sub> {
                    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.debug_struct("ConnectionPublisherSubscriber")
                            .field("meta", &self.meta)
                            .field("quic_version", &self.quic_version)
                            .finish()
                    }
                }

                impl<'a, Sub: Subscriber> EndpointPublisherSubscriber<'a, Sub> {
                    #[inline]
                    pub fn new(
                        meta: builder::EndpointMeta,
                        quic_version: Option<u32>,
                        subscriber: &'a #mode Sub,
                    ) -> Self {
                        Self {
                            meta: meta.into_event(),
                            quic_version,
                            subscriber,
                        }
                    }
                }

                impl<'a, Sub: Subscriber> EndpointPublisher for EndpointPublisherSubscriber<'a, Sub> {
                    #endpoint_publisher_subscriber

                    #[inline]
                    fn quic_version(&self) -> Option<u32> {
                        self.quic_version
                    }
                }

                pub trait ConnectionPublisher {
                    #connection_publisher

                    /// Returns the QUIC version negotiated for the current connection, if any
                    fn quic_version(&self) -> u32;

                    /// Returns the [`Subject`] for the current publisher
                    fn subject(&self) -> api::Subject;
                }

                pub struct ConnectionPublisherSubscriber<'a, Sub: Subscriber> {
                    meta: api::ConnectionMeta,
                    quic_version: u32,
                    subscriber: &'a #mode Sub,
                    context: &'a #mode Sub::ConnectionContext,
                }

                impl<'a, Sub: Subscriber> fmt::Debug for ConnectionPublisherSubscriber<'a, Sub> {
                    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.debug_struct("ConnectionPublisherSubscriber")
                            .field("meta", &self.meta)
                            .field("quic_version", &self.quic_version)
                            .finish()
                    }
                }

                impl<'a, Sub: Subscriber> ConnectionPublisherSubscriber<'a, Sub> {
                    #[inline]
                    pub fn new(
                        meta: builder::ConnectionMeta,
                        quic_version: u32,
                        subscriber: &'a #mode Sub,
                        context: &'a #mode Sub::ConnectionContext
                    ) -> Self {
                        Self {
                            meta: meta.into_event(),
                            quic_version,
                            subscriber,
                            context,
                        }
                    }
                }

                impl<'a, Sub: Subscriber> ConnectionPublisher for ConnectionPublisherSubscriber<'a, Sub> {
                    #connection_publisher_subscriber

                    #[inline]
                    fn quic_version(&self) -> u32 {
                        self.quic_version
                    }

                    #[inline]
                    fn subject(&self) -> api::Subject {
                        self.meta.subject()
                    }
                }
            }

            pub mod metrics {
                use super::*;
                #imports
                use #s2n_quic_core_path::event::metrics::Recorder;

                #[derive(Debug)]
                pub struct Subscriber<S: super::Subscriber>
                    where S::ConnectionContext: Recorder {
                    subscriber: S,
                }

                impl<S: super::Subscriber> Subscriber<S>
                    where S::ConnectionContext: Recorder {
                    pub fn new(subscriber: S) -> Self {
                        Self { subscriber }
                    }
                }

                pub struct Context<R: Recorder> {
                    recorder: R,
                    #metrics_fields
                }

                impl<S: super::Subscriber> super::Subscriber for Subscriber<S>
                    where S::ConnectionContext: Recorder {
                    type ConnectionContext = Context<S::ConnectionContext>;

                    fn create_connection_context(
                        &#mode self,
                        meta: &api::ConnectionMeta,
                        info: &api::ConnectionInfo
                    ) -> Self::ConnectionContext {
                        Context {
                            recorder: self.subscriber.create_connection_context(meta, info),
                            #metrics_fields_init
                        }
                    }

                    #subscriber_metrics
                }

                impl<R: Recorder> Drop for Context<R> {
                    fn drop(&mut self) {
                        #metrics_record
                    }
                }
            }

            #[cfg(any(test, feature = "testing"))]
            pub mod testing {
                use super::*;
                use crate::event::snapshot::Location;
                #imports
                #mutex

                pub mod endpoint {
                    use super::*;

                    pub struct Subscriber {
                        location: Option<Location>,
                        output: #testing_output_type,
                        #endpoint_testing_fields
                    }

                    impl Drop for Subscriber {
                        fn drop(&mut self) {
                            // don't make any assertions if we're already failing the test
                            if std::thread::panicking() {
                                return;
                            }

                            if let Some(location) = self.location.as_ref() {
                                location.snapshot_log(&self.output #lock);
                            }
                        }
                    }

                    impl Subscriber {
                        /// Creates a subscriber with snapshot assertions enabled
                        #[track_caller]
                        pub fn snapshot() -> Self {
                            let mut sub = Self::no_snapshot();
                            sub.location = Location::from_thread_name();
                            sub
                        }

                        /// Creates a subscriber with snapshot assertions enabled
                        #[track_caller]
                        pub fn named_snapshot<Name: core::fmt::Display>(name: Name) -> Self {
                            let mut sub = Self::no_snapshot();
                            sub.location = Some(Location::new(name));
                            sub
                        }

                        /// Creates a subscriber with snapshot assertions disabled
                        pub fn no_snapshot() -> Self {
                            Self {
                                location: None,
                                output: Default::default(),
                                #endpoint_testing_fields_init
                            }
                        }
                    }

                    impl super::super::Subscriber for Subscriber {
                        type ConnectionContext = ();

                        fn create_connection_context(
                            &#mode self,
                            _meta: &api::ConnectionMeta,
                            _info: &api::ConnectionInfo
                        ) -> Self::ConnectionContext {}

                        #endpoint_subscriber_testing
                    }
                }

                #[derive(Debug)]
                pub struct Subscriber {
                    location: Option<Location>,
                    output: #testing_output_type,
                    #testing_fields
                }

                impl Drop for Subscriber {
                    fn drop(&mut self) {
                        // don't make any assertions if we're already failing the test
                        if std::thread::panicking() {
                            return;
                        }

                        if let Some(location) = self.location.as_ref() {
                            location.snapshot_log(&self.output #lock);
                        }
                    }
                }

                impl Subscriber {
                    /// Creates a subscriber with snapshot assertions enabled
                    #[track_caller]
                    pub fn snapshot() -> Self {
                        let mut sub = Self::no_snapshot();
                        sub.location = Location::from_thread_name();
                        sub
                    }

                    /// Creates a subscriber with snapshot assertions enabled
                    #[track_caller]
                    pub fn named_snapshot<Name: core::fmt::Display>(name: Name) -> Self {
                        let mut sub = Self::no_snapshot();
                        sub.location = Some(Location::new(name));
                        sub
                    }

                    /// Creates a subscriber with snapshot assertions disabled
                    pub fn no_snapshot() -> Self {
                        Self {
                            location: None,
                            output: Default::default(),
                            #testing_fields_init
                        }
                    }
                }

                impl super::Subscriber for Subscriber {
                    type ConnectionContext = ();

                    fn create_connection_context(
                        &#mode self,
                        _meta: &api::ConnectionMeta,
                        _info: &api::ConnectionInfo
                    ) -> Self::ConnectionContext {}

                    #subscriber_testing
                }

                #[derive(Debug)]
                pub struct Publisher {
                    location: Option<Location>,
                    output: #testing_output_type,
                    #testing_fields
                }

                impl Publisher {
                    /// Creates a publisher with snapshot assertions enabled
                    #[track_caller]
                    pub fn snapshot() -> Self {
                        let mut sub = Self::no_snapshot();
                        sub.location = Location::from_thread_name();
                        sub
                    }

                    /// Creates a subscriber with snapshot assertions enabled
                    #[track_caller]
                    pub fn named_snapshot<Name: core::fmt::Display>(name: Name) -> Self {
                        let mut sub = Self::no_snapshot();
                        sub.location = Some(Location::new(name));
                        sub
                    }

                    /// Creates a publisher with snapshot assertions disabled
                    pub fn no_snapshot() -> Self {
                        Self {
                            location: None,
                            output: Default::default(),
                            #testing_fields_init
                        }
                    }
                }

                impl super::EndpointPublisher for Publisher {
                    #endpoint_publisher_testing

                    fn quic_version(&self) -> Option<u32> {
                        Some(1)
                    }
                }

                impl super::ConnectionPublisher for Publisher {
                    #connection_publisher_testing

                    fn quic_version(&self) -> u32 {
                        1
                    }

                    fn subject(&self) -> api::Subject {
                        builder::Subject::Connection { id: 0 }.into_event()
                    }
                }

                impl Drop for Publisher {
                    fn drop(&mut self) {
                        // don't make any assertions if we're already failing the test
                        if std::thread::panicking() {
                            return;
                        }

                        if let Some(location) = self.location.as_ref() {
                            location.snapshot_log(&self.output #lock);
                        }
                    }
                }
            }
        ));
    }
}

struct EventInfo<'a> {
    input_path: &'a str,
    output_path: &'a str,
    output_mode: OutputMode,
    s2n_quic_core_path: TokenStream,
    api: TokenStream,
    builder: TokenStream,
    tracing_subscriber_attr: TokenStream,
    tracing_subscriber_def: TokenStream,
}

impl EventInfo<'_> {
    fn s2n_quic() -> Self {
        let tracing_subscriber_def = quote!(
        /// Emits events with [`tracing`](https://docs.rs/tracing)
        #[derive(Clone, Debug)]
        pub struct Subscriber {
            client: tracing::Span,
            server: tracing::Span,
        }

        impl Default for Subscriber {
            fn default() -> Self {
                let root = tracing::span!(target: "s2n_quic", tracing::Level::DEBUG, "s2n_quic");
                let client = tracing::span!(parent: root.id(), tracing::Level::DEBUG, "client");
                let server = tracing::span!(parent: root.id(), tracing::Level::DEBUG, "server");

                Self {
                    client,
                    server,
                }
            }
        }

        impl Subscriber {
            fn parent<M: crate::event::Meta>(&self, meta: &M) -> Option<tracing::Id> {
                match meta.endpoint_type() {
                    api::EndpointType::Client { .. } => self.client.id(),
                    api::EndpointType::Server { .. } => self.server.id(),
                }
            }
        }
        );

        EventInfo {
            input_path: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../s2n-quic-core/events/**/*.rs"
            ),
            output_path: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../s2n-quic-core/src/event/generated.rs"
            ),
            output_mode: OutputMode::Mut,
            s2n_quic_core_path: quote!(crate),
            api: quote!(),
            builder: quote!(),
            tracing_subscriber_attr: quote! {
                #[cfg(feature = "event-tracing")]
            },
            tracing_subscriber_def,
        }
    }

    fn s2n_quic_dc() -> Self {
        let tracing_subscriber_def = quote!(
        /// Emits events with [`tracing`](https://docs.rs/tracing)
        #[derive(Clone, Debug)]
        pub struct Subscriber {
            root: tracing::Span,
        }

        impl Default for Subscriber {
            fn default() -> Self {
                let root = tracing::span!(target: "s2n_quic_dc", tracing::Level::DEBUG, "s2n_quic_dc");

                Self {
                    root,
                }
            }
        }

        impl Subscriber {
            fn parent<M: crate::event::Meta>(&self, _meta: &M) -> Option<tracing::Id> {
                self.root.id()
            }
        }
        );

        EventInfo {
            input_path: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../dc/s2n-quic-dc/events/**/*.rs"
            ),
            output_path: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../dc/s2n-quic-dc/src/event/generated.rs"
            ),
            output_mode: OutputMode::Ref,
            s2n_quic_core_path: quote!(s2n_quic_core),
            api: quote! {
                pub use s2n_quic_core::event::api::{
                    Subject,
                    EndpointType,
                    SocketAddress,
                };
            },
            builder: quote! {
                pub use s2n_quic_core::event::builder::{
                    Subject,
                    EndpointType,
                    SocketAddress,
                };
            },
            tracing_subscriber_attr: quote!(),
            tracing_subscriber_def,
        }
    }
}

fn main() -> Result<()> {
    let event_paths = [EventInfo::s2n_quic(), EventInfo::s2n_quic_dc()];

    for event_info in event_paths {
        let mut files = vec![];

        let input_path = event_info.input_path;

        for path in glob::glob(input_path)? {
            let path = path?;
            eprintln!("loading {}", path.canonicalize().unwrap().display());
            let file = std::fs::read_to_string(path)?;
            files.push(parser::parse(&file).unwrap());
        }

        let mut output = Output {
            mode: event_info.output_mode,
            s2n_quic_core_path: event_info.s2n_quic_core_path,
            api: event_info.api,
            builders: event_info.builder,
            tracing_subscriber_attr: event_info.tracing_subscriber_attr,
            tracing_subscriber_def: event_info.tracing_subscriber_def,
            ..Default::default()
        };

        for file in &files {
            file.to_tokens(&mut output);
        }

        let generated = std::path::Path::new(event_info.output_path)
            .canonicalize()
            .unwrap();

        let mut o = std::fs::File::create(&generated)?;

        macro_rules! put {
            ($($arg:tt)*) => {{
                use std::io::Write;
                writeln!(o, $($arg)*)?;
            }}
        }

        put!("// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.");
        put!("// SPDX-License-Identifier: Apache-2.0");
        put!();
        put!("// DO NOT MODIFY THIS FILE");
        put!("// This file was generated with the `s2n-quic-events` crate and any required");
        put!("// changes should be made there.");
        put!();
        put!("{}", output.to_token_stream());

        let status = std::process::Command::new("rustfmt")
            .arg(&generated)
            .spawn()?
            .wait()?;

        assert!(status.success());

        eprintln!("  wrote {}", generated.display());
    }

    Ok(())
}
