// Copyright (C) 2024 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A [`Stream`] in an ICE [`Agent`]

use alloc::vec::Vec;
use core::net::SocketAddr;

use crate::gathering::GatherPoll;
use stun_proto::Instant;
use stun_proto::agent::{StunError, Transmit};
use stun_proto::types::data::Data;

use crate::agent::{generate_restart_credentials, Agent, AgentError};
use crate::component::{Component, ComponentMut, ComponentState, GatherProgress};
use crate::conncheck::{HandleRecvReply, PendingRecv, RecvIgnorable, RequestRto};

use crate::candidate::{Candidate, TransportType};
//use crate::turn::agent::TurnCredentials;

pub use crate::conncheck::Credentials;
pub use crate::gathering::GatheredCandidate;

use tracing::{info, trace};

/// An ICE [`Stream`]
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Stream<'a> {
    agent: &'a crate::agent::Agent,
    id: usize,
}

impl<'a> Stream<'a> {
    pub(crate) fn from_agent(agent: &'a Agent, id: usize) -> Self {
        Self { agent, id }
    }

    /// The [`Agent`] that handles this [`Stream`].
    pub fn agent(&self) -> &'a crate::agent::Agent {
        self.agent
    }

    /// The stream identifier within a particular ICE [`Agent`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
    /// # use rice_proto::stream::Stream;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let stream = agent.stream(stream_id).unwrap();
    /// assert_eq!(stream.id(), stream_id);
    /// ```
    pub fn id(&self) -> usize {
        self.id
    }

    /// Retrieve a `Component` from this stream.  If the index doesn't exist or a component is not
    /// available at that index, `None` is returned
    ///
    /// # Examples
    ///
    /// Remove a `Component`
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
    /// # use rice_proto::component;
    /// # use rice_proto::component::Component;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let mut stream = agent.mut_stream(stream_id).unwrap();
    /// let component_id = stream.add_component().unwrap();
    /// let component = stream.component(component_id).unwrap();
    /// assert_eq!(component.id(), component::RTP);
    /// assert!(stream.component(component::RTP).is_some());
    /// ```
    ///
    /// Retrieving a `Component` that doesn't exist will return `None`
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
    /// # use rice_proto::component;
    /// # use rice_proto::component::Component;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let stream = agent.stream(stream_id).unwrap();
    /// assert!(stream.component(component::RTP).is_none());
    /// ```
    pub fn component(&self, index: usize) -> Option<Component<'_>> {
        if index < 1 {
            return None;
        }
        let stream_state = self.agent.stream_state(self.id)?;
        if let Some(Some(_component)) = stream_state.components.get(index - 1) {
            Some(Component::from_stream(self.agent, self.id, index))
        } else {
            None
        }
    }

    /// Retreive the previouly set local ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
    /// # use rice_proto::stream::Credentials;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let mut stream = agent.mut_stream(stream_id).unwrap();
    /// let credentials = Credentials {ufrag: "1".to_owned(), passwd: "2".to_owned()};
    /// stream.set_local_credentials(credentials.clone());
    /// assert_eq!(stream.local_credentials(), Some(credentials));
    /// ```
    pub fn local_credentials(&self) -> Option<Credentials> {
        let stream_state = self.agent.stream_state(self.id)?;
        stream_state.local_credentials()
    }

    /// Retreive the previouly set remote ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
    /// # use rice_proto::stream::Credentials;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let mut stream = agent.mut_stream(stream_id).unwrap();
    /// let credentials = Credentials {ufrag: "1".to_owned(), passwd: "2".to_owned()};
    /// stream.set_remote_credentials(credentials.clone());
    /// assert_eq!(stream.remote_credentials(), Some(credentials));
    /// ```
    pub fn remote_credentials(&self) -> Option<Credentials> {
        let stream_state = self.agent.stream_state(self.id)?;
        stream_state.remote_credentials()
    }

    /// Retrieve previously gathered local candidates
    pub fn local_candidates(&self) -> impl Iterator<Item = &'_ Candidate> + '_ {
        let stream_state = self.agent.stream_state(self.id).unwrap();
        let checklist = self
            .agent
            .checklistset
            .list(stream_state.checklist_id)
            .unwrap();
        checklist.local_candidates()
    }

    /// Retrieve previously set remote candidates for connection checks from this stream
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
    /// # use rice_proto::candidate::*;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let mut stream = agent.mut_stream(stream_id).unwrap();
    /// let component_id = stream.add_component().unwrap();
    /// let component = stream.component(component_id).unwrap();
    /// let addr = "127.0.0.1:9999".parse().unwrap();
    /// let candidate = Candidate::builder(
    ///     0,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "0",
    ///     addr
    /// )
    /// .build();
    /// stream.add_remote_candidate(candidate.clone());
    /// let remote_cands = stream.remote_candidates();
    /// assert_eq!(remote_cands.len(), 1);
    /// assert_eq!(remote_cands[0], candidate);
    /// ```
    pub fn remote_candidates(&self) -> &[Candidate] {
        let stream_state = self.agent.stream_state(self.id).unwrap();
        let checklist_id = stream_state.checklist_id;
        let checklist = self.agent.checklistset.list(checklist_id).unwrap();
        checklist.remote_candidates()
    }

    /// Return an `Iterator` over all the component ids in this stream.
    pub fn component_ids_iter(&self) -> impl Iterator<Item = usize> + '_ {
        let stream = self.agent.stream_state(self.id).unwrap();
        stream
            .components
            .iter()
            .flatten()
            .map(|component| component.id)
    }
}

/// A (mutable) ICE stream
#[derive(Debug)]
#[repr(C)]
pub struct StreamMut<'a> {
    agent: &'a mut crate::agent::Agent,
    id: usize,
}

impl<'a> core::ops::Deref for StreamMut<'a> {
    type Target = Stream<'a>;

    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}

impl<'a> StreamMut<'a> {
    pub(crate) fn from_agent(agent: &'a mut Agent, id: usize) -> Self {
        Self { agent, id }
    }

    /// The [`Agent`] that handles this [`Stream`].
    pub fn mut_agent(&'a mut self) -> &'a mut crate::agent::Agent {
        self.agent
    }

    /// Add a `Component` to this stream.
    ///
    /// # Examples
    ///
    /// Add a `Component`
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
    /// # use rice_proto::component;
    /// # use rice_proto::component::Component;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let mut stream = agent.mut_stream(stream_id).unwrap();
    /// let component_id = stream.add_component().unwrap();
    /// let component = stream.component(component_id).unwrap();
    /// assert_eq!(component.id(), component::RTP);
    /// ```
    pub fn add_component(&mut self) -> Result<usize, AgentError> {
        let stream_state = self
            .agent
            .mut_stream_state(self.id)
            .ok_or(AgentError::ResourceNotFound)?;
        let component_id = stream_state.add_component()?;
        let checklist_id = stream_state.checklist_id;
        let checklist = self.agent.checklistset.mut_list(checklist_id).unwrap();
        checklist.add_component(component_id);
        Ok(component_id)
    }

    /// Remove a `Component` from this stream without changing any other component ids.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let mut stream = agent.mut_stream(stream_id).unwrap();
    /// let component_id = stream.add_component().unwrap();
    /// stream.remove_component(component_id);
    /// assert!(stream.component(component_id).is_none());
    /// ```
    pub fn remove_component(&mut self, index: usize) {
        if index < 1 {
            return;
        }
        self.agent.remove_component(self.id, index);
    }

    /// Retrieve mutable access to a component in this stream.  `None` will be returned if the
    /// component does not exist
    pub fn mut_component(&mut self, index: usize) -> Option<ComponentMut<'_>> {
        if index < 1 {
            return None;
        }
        let stream_state = self.agent.mut_stream_state(self.id)?;
        if let Some(Some(_component)) = stream_state.components.get_mut(index - 1) {
            Some(ComponentMut::from_stream(self.agent, self.id, index))
        } else {
            None
        }
    }

    /// Set local ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
    /// # use rice_proto::stream::Credentials;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let mut stream = agent.mut_stream(stream_id).unwrap();
    /// let credentials = Credentials {ufrag: "1".to_owned(), passwd: "2".to_owned()};
    /// stream.set_local_credentials(credentials);
    /// ```
    pub fn set_local_credentials(&mut self, credentials: Credentials) {
        let stream_state = self.agent.mut_stream_state(self.id).unwrap();
        stream_state.set_local_credentials(credentials.clone());
        let checklist_id = stream_state.checklist_id;
        let checklist = self.agent.checklistset.mut_list(checklist_id).unwrap();
        checklist.set_local_credentials(credentials);
    }

    /// Set remote ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
    /// # use rice_proto::stream::Credentials;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let mut stream = agent.mut_stream(stream_id).unwrap();
    /// let credentials = Credentials {ufrag: "1".to_owned(), passwd: "2".to_owned()};
    /// stream.set_remote_credentials(credentials);
    /// ```
    pub fn set_remote_credentials(&mut self, credentials: Credentials) {
        let stream_state = self.agent.mut_stream_state(self.id).unwrap();
        stream_state.set_remote_credentials(credentials.clone());
        let checklist_id = stream_state.checklist_id;
        let checklist = self.agent.checklistset.mut_list(checklist_id).unwrap();
        checklist.set_remote_credentials(credentials);
    }

    /// Restart this stream with explicit local ICE credentials.
    ///
    /// Existing local candidates, sockets, and TURN allocations are preserved; callers must
    /// exchange the new credentials and remote candidates before connectivity checks can complete
    /// again.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
    /// # use rice_proto::stream::Credentials;
    /// # use stun_proto::Instant;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let mut stream = agent.mut_stream(stream_id).unwrap();
    /// let credentials = Credentials::new("ufrag".into(), "a-very-long-password-value".into());
    /// stream.restart(credentials.clone(), Instant::ZERO);
    /// assert_eq!(stream.local_credentials(), Some(credentials));
    /// assert!(stream.remote_credentials().is_none());
    /// ```
    pub fn restart(&mut self, local_credentials: Credentials, now: Instant) {
        let _ = self
            .agent
            .restart_stream_with_credentials(self.id, local_credentials, now);
    }

    /// Restart this stream with fresh random local ICE credentials.
    pub fn restart_with_random_credentials(&mut self, now: Instant) -> Credentials {
        let credentials = generate_restart_credentials();
        self.restart(credentials.clone(), now);
        credentials
    }

    /// Add a remote candidate for connection checks for use with this stream
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
    /// # use rice_proto::candidate::*;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let mut stream = agent.mut_stream(stream_id).unwrap();
    /// let component_id = stream.add_component().unwrap();
    /// let component = stream.component(component_id).unwrap();
    /// let addr = "127.0.0.1:9999".parse().unwrap();
    /// let candidate = Candidate::builder(
    ///     0,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "0",
    ///     addr
    /// )
    /// .build();
    /// stream.add_remote_candidate(candidate);
    /// ```
    #[tracing::instrument(
        skip(self, cand),
        fields(
            stream.id = self.id
        )
    )]
    pub fn add_remote_candidate(&mut self, cand: Candidate) {
        info!("adding remote candidate {:?}", cand);
        let Some(stream_state) = self.agent.mut_stream_state(self.id) else {
            return;
        };
        let checklist_id = stream_state.checklist_id;
        let checklist = self.agent.checklistset.mut_list(checklist_id).unwrap();
        checklist.add_remote_candidate(cand);
    }

    /// Provide the stream with data that has been received on an external socket.  The returned
    /// value indicates what has been done with the data and any application data that has been
    /// received.
    #[tracing::instrument(
        name = "stream_handle_incoming_data",
        skip(self, component_id, transmit),
        fields(
            stream.id = self.id,
            component.id = component_id,
        )
    )]
    pub fn handle_incoming_data<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        component_id: usize,
        transmit: Transmit<T>,
        now: Instant,
    ) -> HandleRecvReply<T> {
        let stream_state = self.agent.mut_stream_state(self.id).unwrap();
        let checklist_id = stream_state.checklist_id;
        // first try to provide the incoming data to the gathering process if it exist
        let ret = stream_state.handle_incoming_data(component_id, &transmit, now);
        if ret.handled {
            return ret;
        }
        if stream_state.component_state(component_id).is_none() {
            return ret;
        };

        // or, provide the data to the connection check component for further processing
        self.agent
            .checklistset
            .incoming_data(checklist_id, component_id, transmit, now)
    }

    /// Send an ignorable error.
    ///
    /// Send an error produced by [`StreamMut::handle_incoming_data`] that could have been (but was not)
    /// handled by another agent listening on the same local port.
    ///
    /// This should be called once all agents listening on the same local socket port have failed
    /// to handle the incoming data.
    #[tracing::instrument(
        name = "stream_send_ignorable_error",
        skip(self),
        fields(
            stream.id = self.id,
        )
    )]
    pub fn send_ignorable_error(&mut self, ignorable: RecvIgnorable) {
        self.agent.checklistset.send_ignorable_error(ignorable)
    }

    /// Poll for any received data.
    ///
    /// Must be called after `handle_incoming_data` if `have_more_data` is `true`.
    pub fn poll_recv(&mut self) -> Option<PendingRecv> {
        let stream_state = self.agent.mut_stream_state(self.id).unwrap();
        let checklist_id = stream_state.checklist_id;

        self.agent
            .checklistset
            .mut_list(checklist_id)
            .and_then(|s| s.poll_recv())
    }

    /// Indicate that no more candidates are expected from the peer.  This may allow the ICE
    /// process to complete.
    #[tracing::instrument(
        skip(self),
        fields(
            component.id = self.id,
        )
    )]
    pub fn end_of_remote_candidates(&mut self) {
        let stream_state = self.agent.mut_stream_state(self.id).unwrap();
        let checklist_id = stream_state.checklist_id;
        let checklist = self.agent.checklistset.mut_list(checklist_id).unwrap();
        checklist.end_of_remote_candidates();
    }

    /// Provide a reply to the
    /// [`AgentPoll::AllocateSocket`](crate::agent::AgentPoll::AllocateSocket) request.  The
    /// `component_id`, `transport`, `from`, and `to` values must match exactly with the request.
    pub fn allocated_socket(
        &mut self,
        component_id: usize,
        transport: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        local_addr: Result<SocketAddr, StunError>,
        now: Instant,
    ) {
        let stream_state = self.agent.mut_stream_state(self.id).unwrap();
        let checklist_id = stream_state.checklist_id;
        let Some(component_state) = stream_state.mut_component_state(component_id) else {
            return;
        };
        if component_state.gather_state == GatherProgress::InProgress {
            if let Some(gather) = component_state.gatherer.as_mut() {
                gather.allocated_socket(transport, from, to, &local_addr);
            }
        }
        self.agent.checklistset.allocated_socket(
            checklist_id,
            component_id,
            transport,
            from,
            to,
            local_addr,
            now,
        );
    }

    /// Add a local candidate for this stream.
    ///
    /// Returns whether the candidate was added internally.
    pub fn add_local_candidate(&mut self, candidate: Candidate) -> bool {
        let stream_state = self.agent.mut_stream_state(self.id).unwrap();
        let checklist_id = stream_state.checklist_id;
        let checklist = self.agent.checklistset.mut_list(checklist_id).unwrap();
        checklist.add_local_candidate(candidate)
    }

    /// Add a local candidate for this stream.
    ///
    /// Returns whether the candidate was added internally.
    pub fn add_local_gathered_candidate(&mut self, candidate: GatheredCandidate) -> bool {
        let stream_state = self.agent.mut_stream_state(self.id).unwrap();
        let checklist_id = stream_state.checklist_id;
        let checklist = self.agent.checklistset.mut_list(checklist_id).unwrap();
        checklist.add_local_gathered_candidate(candidate)
    }

    /// Signal the end of local candidates.  Calling this function may allow ICE processing to
    /// complete.
    pub fn end_of_local_candidates(&mut self) {
        let stream_state = self.agent.mut_stream_state(self.id).unwrap();
        let checklist_id = stream_state.checklist_id;
        let checklist = self.agent.checklistset.mut_list(checklist_id).unwrap();
        checklist.end_of_local_candidates()
    }
}

#[derive(Debug, Default)]
pub(crate) struct StreamState {
    id: usize,
    pub(crate) checklist_id: usize,
    components: Vec<Option<ComponentState>>,
    local_credentials: Option<Credentials>,
    remote_credentials: Option<Credentials>,
}

impl StreamState {
    pub(crate) fn new(id: usize, checklist_id: usize) -> Self {
        Self {
            id,
            checklist_id,
            components: Vec::new(),
            local_credentials: None,
            remote_credentials: None,
        }
    }

    pub(crate) fn component_state(&self, component_id: usize) -> Option<&ComponentState> {
        if component_id < 1 {
            return None;
        }
        if let Some(Some(c)) = self.components.get(component_id - 1) {
            Some(c)
        } else {
            None
        }
    }

    pub(crate) fn mut_component_state(
        &mut self,
        component_id: usize,
    ) -> Option<&mut ComponentState> {
        if component_id < 1 {
            return None;
        }
        if let Some(Some(c)) = self.components.get_mut(component_id - 1) {
            Some(c)
        } else {
            None
        }
    }

    /// The id of the [`Stream`]
    pub(crate) fn id(&self) -> usize {
        self.id
    }

    #[tracing::instrument(
        name = "stream_add_component",
        skip(self),
        fields(
            stream.id = self.id
        )
    )]
    pub(crate) fn add_component(&mut self) -> Result<usize, AgentError> {
        let index = self
            .components
            .iter()
            .enumerate()
            .find(|c| c.1.is_none())
            .unwrap_or((self.components.len(), &None))
            .0;
        info!("adding component {}", index + 1);
        if matches!(self.components.get(index), Some(Some(_))) {
            return Err(AgentError::AlreadyExists);
        }
        while self.components.len() <= index {
            self.components.push(None);
        }
        let component = ComponentState::new(index + 1);
        self.components[index] = Some(component);
        trace!("Added component at index {}", index);
        Ok(index + 1)
    }

    pub(crate) fn remove_component(&mut self, component_id: usize) -> bool {
        if component_id < 1 || component_id > self.components.len() {
            return false;
        }
        self.components[component_id - 1] = None;
        true
    }

    #[tracing::instrument(
        skip(self),
        fields(
            stream.id = self.id
        )
    )]
    pub(crate) fn set_local_credentials(&mut self, credentials: Credentials) {
        info!("setting");
        self.local_credentials = Some(credentials.clone());
    }

    pub(crate) fn local_credentials(&self) -> Option<Credentials> {
        self.local_credentials.clone()
    }

    #[tracing::instrument(
        skip(self),
        fields(
            stream.id = self.id()
        )
    )]
    pub(crate) fn set_remote_credentials(&mut self, credentials: Credentials) {
        info!("setting");
        self.remote_credentials = Some(credentials.clone());
    }

    pub(crate) fn clear_remote_credentials(&mut self) {
        self.remote_credentials = None;
    }

    pub(crate) fn remote_credentials(&self) -> Option<Credentials> {
        self.remote_credentials.clone()
    }

    pub(crate) fn component_ids_iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.components.iter().flatten().map(|component| component.id)
    }

    pub(crate) fn clear_selected_pairs(&mut self) {
        for component in self.components.iter_mut().flatten() {
            component.clear_selected_pair();
        }
    }

    pub(crate) fn handle_incoming_data<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        component_id: usize,
        transmit: &Transmit<T>,
        now: Instant,
    ) -> HandleRecvReply<T> {
        let Some(component) = self.mut_component_state(component_id) else {
            return HandleRecvReply::default();
        };
        if component.gather_state != GatherProgress::InProgress {
            return HandleRecvReply::default();
        }
        let Some(gather) = component.gatherer.as_mut() else {
            return HandleRecvReply::default();
        };
        // XXX: is this enough to successfully route to the gatherer over the
        // connection check or component received handling?
        let mut ret = HandleRecvReply::default();
        ret.handled = gather.handle_data(transmit, now);
        ret
    }

    #[tracing::instrument(ret, level = "trace", skip(self))]
    pub(crate) fn poll_gather(&mut self, now: Instant) -> GatherPoll {
        let mut lowest_wait = None;
        for component in self.components.iter_mut() {
            let Some(component) = component else {
                continue;
            };
            let Some(gatherer) = component.gatherer.as_mut() else {
                continue;
            };
            if component.gather_state != GatherProgress::InProgress {
                continue;
            }

            match gatherer.poll(now) {
                GatherPoll::WaitUntil(wait) => {
                    if let Some(check_wait) = lowest_wait {
                        if wait < check_wait {
                            lowest_wait = Some(wait);
                        }
                    } else {
                        lowest_wait = Some(wait);
                    }
                }
                GatherPoll::Complete(component_id) => {
                    component.gather_state = GatherProgress::Completed;
                    return GatherPoll::Complete(component_id);
                }
                GatherPoll::Finished => (),
                other => return other,
            }
        }
        if let Some(lowest_wait) = lowest_wait {
            GatherPoll::WaitUntil(lowest_wait)
        } else {
            GatherPoll::Finished
        }
    }

    pub(crate) fn poll_gather_transmit(
        &mut self,
        now: Instant,
    ) -> Option<(usize, Transmit<Data<'_>>)> {
        for component in self.components.iter_mut() {
            let Some(component) = component else {
                continue;
            };
            let Some(gatherer) = component.gatherer.as_mut() else {
                continue;
            };
            if component.gather_state != GatherProgress::InProgress {
                continue;
            }

            if let Some(transmit) = gatherer.poll_transmit(now) {
                return Some((component.id, transmit));
            }
        }
        None
    }

    pub(crate) fn set_request_retransmits(&mut self, rto: RequestRto) {
        for component in self.components.iter_mut() {
            let Some(component) = component else {
                continue;
            };
            let Some(gatherer) = component.gatherer.as_mut() else {
                continue;
            };

            gatherer.set_request_retransmits(rto.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::time::Duration;

    use crate::agent::{Agent, AgentPoll};
    use crate::candidate::{Candidate, CandidateType, TcpType, TransportType};
    use crate::component::ComponentConnectionState;
    use stun_proto::auth::ShortTermAuth;
    use stun_proto::types::attribute::XorMappedAddress;
    use stun_proto::types::message::{
        IntegrityAlgorithm, Message, MessageWrite, MessageWriteExt, MessageWriteVec,
    };

    fn host_candidate(component_id: usize, addr: SocketAddr) -> Candidate {
        Candidate::builder(
            component_id,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .priority(1234)
        .build()
    }

    fn reply_to_check(
        agent: &mut Agent,
        stream_id: usize,
        component_id: usize,
        transmit: crate::agent::AgentTransmit,
        remote: &Credentials,
        now: Instant,
    ) {
        let request = Message::from_bytes(&transmit.transmit.data).unwrap();
        let mut auth = ShortTermAuth::new();
        auth.set_credentials(remote.clone().into(), IntegrityAlgorithm::Sha1);
        let mut response = Message::builder_success(&request, MessageWriteVec::new());
        response
            .add_attribute(&XorMappedAddress::new(transmit.transmit.from, request.transaction_id()))
            .unwrap();
        let mut response = auth.sign_outgoing_message(response).unwrap();
        response.add_fingerprint().unwrap();
        let response = response.finish();
        let reply = Transmit::new(
            response.as_slice(),
            transmit.transmit.transport,
            transmit.transmit.to,
            transmit.transmit.from,
        );
        let handled = agent
            .mut_stream(stream_id)
            .unwrap()
            .handle_incoming_data(component_id, reply, now);
        assert!(handled.handled);
    }

    fn complete_check_cycle(
        agent: &mut Agent,
        stream_id: usize,
        component_id: usize,
        remote: &Credentials,
        mut now: Instant,
    ) -> Instant {
        for _ in 0..16 {
            match agent.poll(now) {
                AgentPoll::ComponentStateChange(change) => {
                    assert_eq!(change.stream_id, stream_id);
                    assert_eq!(change.component_id, component_id);
                    assert!(
                        matches!(
                            change.state,
                            ComponentConnectionState::Connecting | ComponentConnectionState::Connected
                        ),
                        "unexpected component state {change:?}"
                    );
                }
                AgentPoll::SelectedPair(selected) => {
                    assert_eq!(selected.stream_id, stream_id);
                    assert_eq!(selected.component_id, component_id);
                    return now;
                }
                AgentPoll::WaitUntil(wait) => {
                    now = wait;
                }
                other => panic!("unexpected poll result during conncheck cycle: {other:?}"),
            }
            if let Some(transmit) = agent.poll_transmit(now) {
                reply_to_check(agent, stream_id, component_id, transmit, remote, now);
            }
        }
        panic!("connectivity checks did not complete");
    }

    #[test]
    fn getters_setters() {
        let _log = crate::tests::test_init_log();
        let lcreds = Credentials::new("luser".into(), "lpass".into());
        let rcreds = Credentials::new("ruser".into(), "rpass".into());

        let mut agent = Agent::default();
        let stream_id = agent.add_stream();
        let mut stream = agent.mut_stream(stream_id).unwrap();
        assert!(stream.component(0).is_none());
        let comp_id = stream.add_component().unwrap();
        assert_eq!(comp_id, stream.component(comp_id).unwrap().id());

        stream.set_local_credentials(lcreds.clone());
        assert_eq!(stream.local_credentials().unwrap(), lcreds);
        stream.set_remote_credentials(rcreds.clone());
        assert_eq!(stream.remote_credentials().unwrap(), rcreds);
    }

    /// After local gathering completes, TCP connectivity checks still request a socket via
    /// [`AgentPoll::AllocateSocket`]. `StreamMut::allocated_socket` must forward that to the
    /// checklist (not only to the gatherer while gathering is in progress).
    #[test]
    fn allocated_socket_reaches_checklist_after_gathering() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let local_bind: SocketAddr = "192.168.1.1:1000".parse().unwrap();

        let mut agent = Agent::default();
        let stream_id = agent.add_stream();
        let component_id = agent
            .mut_stream(stream_id)
            .unwrap()
            .add_component()
            .unwrap();
        {
            let mut stream = agent.mut_stream(stream_id).unwrap();
            stream.set_local_credentials(Credentials::new("luser".into(), "lpass".into()));
            stream.set_remote_credentials(Credentials::new("ruser".into(), "rpass".into()));
            stream
                .mut_component(component_id)
                .unwrap()
                .gather_candidates(&[(TransportType::Tcp, local_bind)], &[], &[])
                .unwrap();
        }

        let mut gathering_done = false;
        while !gathering_done {
            match agent.poll(now) {
                AgentPoll::GatheredCandidate(gathered) => {
                    agent
                        .mut_stream(stream_id)
                        .unwrap()
                        .add_local_gathered_candidate(gathered.gathered);
                }
                AgentPoll::GatheringComplete(complete) => {
                    assert_eq!(complete.component_id, component_id);
                    agent
                        .mut_stream(stream_id)
                        .unwrap()
                        .end_of_local_candidates();
                    gathering_done = true;
                }
                other => panic!("unexpected poll during gathering: {other:?}"),
            }
        }

        let remote_addr: SocketAddr = "192.168.1.2:2000".parse().unwrap();
        let remote = Candidate::builder(
            component_id,
            CandidateType::Host,
            TransportType::Tcp,
            "1",
            remote_addr,
        )
        .tcp_type(TcpType::Passive)
        .priority(5000)
        .build();
        agent
            .mut_stream(stream_id)
            .unwrap()
            .add_remote_candidate(remote);
        agent
            .mut_stream(stream_id)
            .unwrap()
            .end_of_remote_candidates();

        let AgentPoll::AllocateSocket(alloc) = agent.poll(now) else {
            panic!("expected AllocateSocket for TCP connectivity check");
        };
        assert_eq!(alloc.component_id, component_id);
        assert_eq!(alloc.transport, TransportType::Tcp);

        let bound: SocketAddr = "192.168.1.1:15000".parse().unwrap();
        agent.mut_stream(stream_id).unwrap().allocated_socket(
            alloc.component_id,
            alloc.transport,
            alloc.from,
            alloc.to,
            Ok(bound),
            now,
        );

        assert!(
            agent.poll_transmit(now).is_some(),
            "checklist should emit STUN after allocated_socket"
        );
    }

    #[test]
    fn restart_preserves_local_candidates_and_clears_remote_credentials() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut agent = Agent::default();
        let stream_id = agent.add_stream();
        let component_id = agent.mut_stream(stream_id).unwrap().add_component().unwrap();
        let old_local = Credentials::new("luser".into(), "long-local-password-value".into());
        let old_remote = Credentials::new("ruser".into(), "long-remote-password-value".into());
        let local_candidate = host_candidate(component_id, "10.0.0.1:1000".parse().unwrap());
        {
            let mut stream = agent.mut_stream(stream_id).unwrap();
            stream.set_local_credentials(old_local);
            stream.set_remote_credentials(old_remote);
            assert!(stream.add_local_candidate(local_candidate.clone()));
            stream.add_remote_candidate(host_candidate(component_id, "10.0.0.2:2000".parse().unwrap()));
            stream.end_of_local_candidates();
            stream.end_of_remote_candidates();
        }

        let before = agent
            .stream(stream_id)
            .unwrap()
            .local_candidates()
            .cloned()
            .collect::<Vec<_>>();
        let new_local = Credentials::new("next".into(), "replacement-password-value".into());
        agent.mut_stream(stream_id).unwrap().restart(new_local.clone(), now);

        let stream = agent.stream(stream_id).unwrap();
        let after = stream.local_candidates().cloned().collect::<Vec<_>>();
        assert_eq!(after, before);
        assert_eq!(stream.local_credentials(), Some(new_local.clone()));
        assert!(stream.remote_credentials().is_none());

        let checklist_id = agent.stream_state(stream_id).unwrap().checklist_id;
        let checklist = agent.checklistset.list(checklist_id).unwrap();
        assert_eq!(checklist.local_credentials(), &new_local);
        assert!(checklist.remote_credentials().is_none());

        match agent.poll(now) {
            AgentPoll::ComponentStateChange(change) => {
                assert_eq!(change.component_id, component_id);
                assert_eq!(change.state, ComponentConnectionState::Connecting);
            }
            other => panic!("expected restart to reset component state, got {other:?}"),
        }
        assert!(
            !matches!(agent.poll(now), AgentPoll::RemoveSocket(_)),
            "restart must preserve sockets backing local candidates"
        );
    }

    #[test]
    fn restart_rearms_end_of_candidates_and_reselects_pair() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let config = crate::consent::Config {
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(30),
        };
        let mut agent = Agent::builder()
            .controlling(true)
            .consent_freshness_config(config)
            .build();
        let stream_id = agent.add_stream();
        let component_id = agent.mut_stream(stream_id).unwrap().add_component().unwrap();
        let local_addr: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let remote_addr: SocketAddr = "10.0.0.2:2000".parse().unwrap();
        let local_candidate = host_candidate(component_id, local_addr);
        let remote_candidate = host_candidate(component_id, remote_addr);
        let first_local = Credentials::new("luser".into(), "first-local-password-value".into());
        let first_remote = Credentials::new("ruser".into(), "first-remote-password-value".into());
        {
            let mut stream = agent.mut_stream(stream_id).unwrap();
            stream.set_local_credentials(first_local);
            stream.set_remote_credentials(first_remote.clone());
            assert!(stream.add_local_candidate(local_candidate.clone()));
            stream.add_remote_candidate(remote_candidate.clone());
            stream.end_of_local_candidates();
            stream.end_of_remote_candidates();
        }

        let mut now = complete_check_cycle(&mut agent, stream_id, component_id, &first_remote, now);
        match agent.poll(now) {
            AgentPoll::ComponentStateChange(change) => {
                assert_eq!(change.component_id, component_id);
                assert_eq!(change.state, ComponentConnectionState::Connected);
            }
            other => panic!("expected Connected after initial SelectedPair, got {other:?}"),
        }
        assert_eq!(agent.consent_freshness.as_ref().unwrap().len(), 1);

        let second_local = agent
            .mut_stream(stream_id)
            .unwrap()
            .restart_with_random_credentials(now);
        assert!(second_local.ufrag.len() >= 4);
        assert!(second_local.passwd.len() >= 22);
        assert_eq!(agent.consent_freshness.as_ref().unwrap().len(), 0);

        match agent.poll(now) {
            AgentPoll::ComponentStateChange(change) => {
                assert_eq!(change.component_id, component_id);
                assert_eq!(change.state, ComponentConnectionState::Connecting);
            }
            other => panic!("expected restart to emit Connecting, got {other:?}"),
        }

        let second_remote = Credentials::new("rnew".into(), "second-remote-password-value".into());
        {
            let mut stream = agent.mut_stream(stream_id).unwrap();
            assert_eq!(stream.local_credentials(), Some(second_local.clone()));
            assert!(stream.remote_credentials().is_none());
            stream.set_remote_credentials(second_remote.clone());
            stream.add_remote_candidate(remote_candidate);
            stream.end_of_local_candidates();
            stream.end_of_remote_candidates();
        }

        now = complete_check_cycle(&mut agent, stream_id, component_id, &second_remote, now);
        assert_eq!(agent.consent_freshness.as_ref().unwrap().len(), 1);
        assert!(!matches!(agent.poll(now), AgentPoll::RemoveSocket(_)));
    }

    #[test]
    fn remove_component_removes_resources_and_reuses_slot() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut agent = Agent::default();
        let stream_id = agent.add_stream();
        let (component1, component2) = {
            let mut stream = agent.mut_stream(stream_id).unwrap();
            let component1 = stream.add_component().unwrap();
            let component2 = stream.add_component().unwrap();
            assert!(stream.add_local_candidate(host_candidate(component1, "10.0.0.1:1000".parse().unwrap())));
            assert!(stream.add_local_candidate(host_candidate(component2, "10.0.0.1:1002".parse().unwrap())));
            (component1, component2)
        };

        agent
            .mut_stream(stream_id)
            .unwrap()
            .remove_component(component1);
        let stream = agent.stream(stream_id).unwrap();
        assert!(stream.component(component1).is_none());
        assert!(stream.component(component2).is_some());
        assert_eq!(
            stream
                .local_candidates()
                .map(|candidate| candidate.component_id)
                .collect::<Vec<_>>(),
            vec![component2]
        );

        let AgentPoll::RemoveSocket(removed) = agent.poll(now) else {
            panic!("expected removed component socket");
        };
        assert_eq!(removed.stream_id, stream_id);
        assert_eq!(removed.component_id, component1);

        let reused = agent.mut_stream(stream_id).unwrap().add_component().unwrap();
        assert_eq!(reused, component1);
    }
}
