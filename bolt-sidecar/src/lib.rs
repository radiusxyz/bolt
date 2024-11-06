#![doc = include_str!("../README.md")]
#![warn(missing_debug_implementations, missing_docs, rustdoc::all)]
#![deny(unused_must_use, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

/// All APIs in use by the sidecar.
pub mod api;

/// Different client types for interacting with APIs
mod client;

/// Telemetry and metrics utilities
pub mod telemetry;

/// Common types and compatibility utilities
mod common;

/// Driver for the sidecar, which manages the main event loop
pub mod driver;
pub use driver::SidecarDriver;

/// Functionality for building local block templates that can
/// be used as a fallback for proposers. It's also used to keep
/// any intermediary state that is needed to simulate EVM execution
pub mod builder;
pub use builder::LocalBuilder;

/// Configuration and command-line argument parsing
pub mod config;

/// Crypto utilities, including BLS and ECDSA
pub mod crypto;

/// Primitive types and utilities
pub mod primitives;

///The `state` module is responsible for keeping a local copy of relevant state that is needed
/// to simulate commitments against. It is updated on every block.
/// It consists of both execution and consensus states.
pub mod state;

/// The signers available to the sidecar
pub mod signer;

/// Utilities and contracts wrappers for interacting with the Bolt registry
pub mod chain_io;

/// Utilities for testing
#[cfg(test)]
mod test_util;
