// SPDX-License-Identifier: Apache-2.0

//! The threads the parser may run on.

use core::marker::PhantomData;
use std::io;
use std::thread;

/// The stack of a parser thread: 16 MiB.
///
/// The parser sizes its own depth limit from the stack it finds, up to
/// 2 MiB, and the decoder of its result recurses up to a fixed depth. With
/// 1 MiB a debug build was seen to overflow; 8 MiB held for every nesting
/// that was tried, and this is twice that. The memory is only reserved: a
/// page counts once it is touched.
pub const PARSER_STACK_BYTES: usize = 16 * 1024 * 1024;

/// Proof that the code holding it runs on a parser thread.
///
/// Only [`spawn_parser_thread`] and [`on_parser_thread`] make one, and it
/// can be neither sent to nor shared with another thread, so a function
/// that takes one cannot be called from a thread with a smaller stack.
#[derive(Debug)]
pub struct ParserThread {
    /// A raw pointer is neither `Send` nor `Sync`.
    pinned: PhantomData<*const ()>,
}

impl ParserThread {
    const fn new() -> Self {
        Self {
            pinned: PhantomData,
        }
    }
}

/// Starts a named parser thread that runs `body` and ends when it returns.
///
/// # Errors
///
/// Returns the error of the operating system when it cannot start a thread.
pub fn spawn_parser_thread<F>(name: String, body: F) -> io::Result<thread::JoinHandle<()>>
where
    F: FnOnce(&ParserThread) + Send + 'static,
{
    thread::Builder::new()
        .name(name)
        .stack_size(PARSER_STACK_BYTES)
        .spawn(move || body(&ParserThread::new()))
}

/// Runs `body` on a parser thread of its own and waits for it. This is for
/// tests and tools; the proxy keeps a pool of threads instead.
///
/// # Errors
///
/// Returns the error of the operating system when it cannot start a thread,
/// and an error of kind `Other` when `body` panicked.
pub fn on_parser_thread<T, F>(body: F) -> io::Result<T>
where
    T: Send,
    F: FnOnce(&ParserThread) -> T + Send,
{
    thread::scope(|scope| {
        thread::Builder::new()
            .name("pgsnare-sql".to_owned())
            .stack_size(PARSER_STACK_BYTES)
            .spawn_scoped(scope, move || body(&ParserThread::new()))?
            .join()
            .map_err(|_| io::Error::other("the parser thread panicked"))
    })
}
