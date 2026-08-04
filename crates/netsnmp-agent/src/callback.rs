//! Broadcast bus for agent callbacks.
//!
//! [`CallbackBus`] is a thin wrapper over [`tokio::sync::broadcast`] used by
//! the agent to fan out a single stream of events (received traps/notifications,
//! alarm-driven refreshes, handler completions) to any number of concurrent
//! subscribers. It mirrors the "callback chain" plumbing in the C agent
//! (`agent/agent_callbacks.c`, `snmplib/callback.c`) where a list of handlers
//! is invoked for a given event — here each subscriber is one such handler
//! consuming the event asynchronously.
//!
//! Messages must be cheaply cloneable (`T: Clone`) because the broadcast channel
//! clones the value once per active receiver. Subscribers are `Receiver<T>`s
//! from `tokio::sync::broadcast` and follow its semantics: a lagging receiver
//! misses the oldest messages past the channel's capacity.

use tokio::sync::broadcast;

/// A fan-out bus that delivers cloneable messages to all current subscribers.
///
/// Wraps [`tokio::sync::broadcast::Sender`]; derive [`Clone`] to hand out cheap
/// handles to publishers (the underlying channel is reference-counted and lives
/// until the last sender and all receivers are dropped).
///
/// # Example
/// ```no_run
/// use netsnmp_agent::CallbackBus;
///
/// # async fn run() {
/// let bus: CallbackBus<u32> = CallbackBus::new(16);
/// let mut sub = bus.subscribe();
/// bus.publish(7);
/// assert_eq!(sub.recv().await, Ok(7));
/// # }
/// ```
pub struct CallbackBus<T>
where
    T: Clone + Send + 'static,
{
    tx: broadcast::Sender<T>,
}

impl<T> Clone for CallbackBus<T>
where
    T: Clone + Send + 'static,
{
    fn clone(&self) -> Self {
        CallbackBus {
            tx: self.tx.clone(),
        }
    }
}

impl<T> CallbackBus<T>
where
    T: Clone + Send + 'static,
{
    /// Create a bus with the given per-receiver history `capacity`.
    ///
    /// `capacity` is the maximum number of values kept for slow receivers; a
    /// receiver that falls further behind sees [`broadcast::error::RecvError`]
    /// (`Lagged`) and continues with the newest values. See the `tokio` docs
    /// for full details.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        CallbackBus { tx }
    }

    /// Subscribe to the bus, returning a receiver that yields subsequent
    /// [`Self::publish`]ed values.
    pub fn subscribe(&self) -> broadcast::Receiver<T> {
        self.tx.subscribe()
    }

    /// Publish `msg` to every current subscriber.
    ///
    /// Returns the number of receivers that received the value (zero if there
    /// are no subscribers, in which case the value is simply dropped). Never
    /// panics: a send with no receivers reports `Err(SendError)` which we map
    /// to `0`.
    pub fn publish(&self, msg: T) -> usize {
        self.tx.send(msg).unwrap_or(0)
    }

    /// The current number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl<T> std::fmt::Debug for CallbackBus<T>
where
    T: Clone + Send + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackBus")
            .field("subscribers", &self.subscriber_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn multiple_subscribers_receive() {
        let bus: CallbackBus<u32> = CallbackBus::new(8);
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);

        assert_eq!(bus.publish(7), 2);
        assert_eq!(a.recv().await, Ok(7));
        assert_eq!(b.recv().await, Ok(7));
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_ok() {
        let bus: CallbackBus<u32> = CallbackBus::new(8);
        assert_eq!(bus.subscriber_count(), 0);
        // Returns 0 and does not panic; a later subscriber does not retroactively
        // receive the dropped value.
        assert_eq!(bus.publish(42), 0);

        let mut sub = bus.subscribe();
        bus.publish(99);
        assert_eq!(sub.recv().await, Ok(99));
    }

    #[tokio::test]
    async fn clone_shares_channel() {
        let bus: CallbackBus<u32> = CallbackBus::new(4);
        let cloned = bus.clone();
        let mut sub = cloned.subscribe();
        bus.publish(1);
        assert_eq!(sub.recv().await, Ok(1));
        assert_eq!(bus.subscriber_count(), cloned.subscriber_count());
    }
}
