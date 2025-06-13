// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Utility functions.

use anyhow::anyhow;
#[cfg(test)]
use parking_lot::ReentrantMutex;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use worker::State;

/// Returns the current Unix timestamp at millisecond precision.
#[cfg(not(test))]
pub(crate) fn now_millis() -> u64 {
    worker::Date::now().as_millis()
}

#[cfg(test)]
static GLOBAL_TIME: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static FREEZE_TIME: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub(crate) static TIME_MUX: ReentrantMutex<()> = ReentrantMutex::new(());

#[cfg(test)]
pub(crate) fn set_freeze_time(b: bool) {
    FREEZE_TIME.store(b, Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn set_global_time(time: u64) {
    GLOBAL_TIME.store(time, Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn now_millis() -> u64 {
    let _lock = TIME_MUX.lock();
    if FREEZE_TIME.load(Ordering::Relaxed) {
        GLOBAL_TIME.load(Ordering::Relaxed)
    } else {
        GLOBAL_TIME.fetch_add(1, Ordering::Relaxed)
    }
}

/// Retrieve the
/// [name](https://developers.cloudflare.com/durable-objects/api/id/#name) that
/// was used to create a Durable Object Id with `id_from_name`. The signature of
/// this function is a little funny since the only way to access the `State`'s
/// inner `DurableObjectState` is via the `_inner()` method which takes
/// ownership of the state. Thus, we just re-derive the State from the inner
/// state and return it in case the calling function still needs it.
///
/// # Errors
///
/// Returns an error if the 'name' property is not present, for example if the
/// object was created with a random ID.
pub fn get_durable_object_name(state: State) -> Result<(State, String), anyhow::Error> {
    let inner_state = state._inner();
    let id = inner_state
        .id()
        .map_err(|e| anyhow!("could not get state obj id: {:?}", e))?;
    let obj = js_sys::Object::from(id);
    let name = js_sys::Reflect::get(&obj, &"name".into())
        .map_err(|e| anyhow!("could not get `name` field from state object: {:?}", e))?
        .as_string()
        .unwrap_or_default();
    Ok((State::from(inner_state), name))
}
