module counter::counter {
    /// A simple Counter object stored on-chain
    public struct Counter has key {
        id: UID,
        value: u64,
    }

    /// Create a new Counter with value 0
    fun new(ctx: &mut TxContext): Counter {
        Counter {
            id: object::new(ctx), // 'object' is already in scope globally
            value: 0,
        }
    }

    /// Publish a new counter object
    entry fun create_counter(ctx: &mut TxContext) {
        let counter = new(ctx);
        transfer::share_object(counter);
    }

    /// Increment the counter
    public fun increment(counter: &mut Counter) {
        counter.value = counter.value + 1;
    }

    /// Decrement the counter (safe: won’t go below 0)
    public fun decrement(counter: &mut Counter) {
        if (counter.value > 0) {
            counter.value = counter.value - 1;
        }
    }

    /// Reset the counter back to 0
    public fun reset(counter: &mut Counter) {
        counter.value = 0;
    }
}
