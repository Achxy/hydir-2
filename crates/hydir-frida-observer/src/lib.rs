//! Optional Frida runtime observer. The normal workspace build needs no devkit.

pub mod transport;

#[cfg(all(target_os = "linux", feature = "frida-runtime"))]
pub mod worker;

#[cfg(all(target_os = "linux", feature = "frida-runtime"))]
mod runtime;
#[cfg(all(target_os = "linux", feature = "frida-runtime"))]
pub use runtime::inside;
#[cfg(all(target_os = "linux", feature = "frida-runtime"))]
pub use runtime::observe;
