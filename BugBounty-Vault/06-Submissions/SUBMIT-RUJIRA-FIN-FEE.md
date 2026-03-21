## Summary

In FIN's `execute_new_order` function, when a new limit order crosses the spread and gets partially filled as a taker swap, the taker fee is deducted from the user's return amount but is never forwarded to `fee_address`. Unlike the `DoSwap` handler which explicitly sends fees via `BankMsg::Send`, the `execute_new_order` path completely omits fee accounting. The fee tokens remain permanently locked in the contract with no recovery mechanism.

## Vulnerability Detail

When a user places a new limit order that crosses the existing spread, FIN first executes a taker swap against the opposite side of the book, then places the remaining amount as a maker order. The taker swap correctly deducts `fee_taker` from the return via the `Swapper`:

In [`packages/rujira-rs/src/exchange/swapper.rs`](https://gitlab.com/thorchain/rujira/-/blob/main/packages/rujira-rs/src/exchange/swapper.rs) lines 65-69:
```rust
let fee = Decimal::from_ratio(self.returned, 1u128)
    .mul(self.fee)
    .to_uint_ceil();
self.returned -= fee;
```

The fee is deducted from `returned`, so the user correctly receives less. However, in [`contracts/rujira-fin/src/order_manager.rs`](https://gitlab.com/thorchain/rujira/-/blob/main/contracts/rujira-fin/src/order_manager.rs) lines 119-163, the `execute_new_order` function never adds `swap.fee_amount` to any fee accumulator:

```rust
fn execute_new_order(&mut self, storage, swap_iter, pool, side, target, oracle) {
    if let Some(target) = target {
        let mut swapper = Swapper::new(..., self.config.fee_taker);
        let mut swap = { swapper.swap(&mut iter)? };
        let order = pool.create_order(storage, &self.timestamp, &self.owner, swap.remaining_offer)?;
        if !swap.return_amount.is_zero() {
            let commit = swapper.commit(storage)?;
            self.messages.append(&mut commit.to_msgs(...)?);
            self.receive += coin(swap.return_amount.u128(), ...);
            self.receive = (self.receive.clone() - coin(swap.consumed_offer.u128(), ...))?;
        }
        self.send += coin(order.amount().u128(), ...);
        // BUG: swap.fee_amount is NEVER added to self.fees
        // Compare with DoSwap in contract.rs line 153 which does: fees += coin(res.fee_amount...)
    }
}
```

Compare with the `DoSwap` handler in [`contracts/rujira-fin/src/contract.rs`](https://gitlab.com/thorchain/rujira/-/blob/main/contracts/rujira-fin/src/contract.rs) line 153 which correctly accounts for fees:

```rust
// DoSwap handler (CORRECT):
fees += coin(res.fee_amount.u128(), config.denoms.bid(&side));  // line 153
fees.normalize();
if !fees.is_empty() {
    messages.push(CosmosMsg::Bank(BankMsg::Send {
        to_address: config.fee_address.to_string(),    // Sent to fee recipient
        amount: fees.into_vec(),
    }))
}
```

The `execute_new_order` path has NO equivalent fee forwarding. The `swapper.commit()` method only returns market-maker commitment data — it has zero fee-handling logic. The `self.fees` field is never incremented in `execute_new_order`, unlike `maybe_withdraw` (line 184) which correctly does `self.fees += fees`.

## Proof of Concept

1. FIN has a BTC/USDC pair with existing sell orders at price 50,000
2. User places a limit buy order at price 50,100 (crosses the spread)
3. `execute_new_order` triggers a taker swap against the sell orders at 50,000
4. The `Swapper` deducts `fee_taker` (e.g., 0.1%) from the BTC return
5. User receives BTC minus fee — correct from user's perspective
6. The fee amount in BTC remains in the FIN contract's bank balance
7. `self.fees` is never incremented — fee is never sent to `config.fee_address`
8. The fee tokens are permanently locked in the contract

This occurs on **every** limit order that crosses the spread and gets a taker fill during placement. Over time, the accumulated fees grow proportionally to trading volume.

## Impact

- **Permanent loss of protocol fee revenue**: Every limit-order crossing accumulates taker fees that are never forwarded to `fee_address`
- **Tokens permanently locked**: No function exists to recover these orphaned tokens from the contract
- **Scales with volume**: The loss grows linearly with the number of limit orders that cross the spread
- **Affects all FIN pairs**: Every FIN orderbook pair contract is affected since they share the same `order_manager.rs` logic

This qualifies as **theft of unclaimed funds (yield/fees)** — the protocol earns the fee (deducted from user) but never receives it.

## Recommended Mitigation

Add fee accounting in `execute_new_order`, matching the pattern used in `DoSwap` and `maybe_withdraw`:

```rust
fn execute_new_order(&mut self, ...) -> Result<(), ContractError> {
    if let Some(target) = target {
        // ... existing swap logic ...
        if !swap.return_amount.is_zero() {
            let commit = swapper.commit(storage)?;
            self.events.append(&mut swap.events);
            self.messages.append(&mut commit.to_msgs(...)?);
            self.receive += coin(swap.return_amount.u128(), self.config.denoms.ask(side));
            self.receive = (self.receive.clone()
                - coin(swap.consumed_offer.u128(), self.config.denoms.bid(side)))?;

            // ADD: Forward taker fees to fee_address
            self.fees += coin(swap.fee_amount.u128(), self.config.denoms.ask(side));
        }
        // ... rest unchanged ...
    }
}
```
