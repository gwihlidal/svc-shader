extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate bincode;
extern crate dotenv;
extern crate failure;
extern crate filebuffer;
extern crate futures;
extern crate futures_cpupool;
extern crate glob;
extern crate normalize_line_endings;
extern crate prost;
extern crate prost_derive;
extern crate prost_types;
extern crate sha2;
extern crate smush;
extern crate tower_grpc;
extern crate uuid;
#[macro_use]
extern crate cfg_if;
extern crate chashmap;
extern crate scoped_threadpool;
#[macro_use]
extern crate serde_derive;
extern crate byteorder;
extern crate include_merkle;
extern crate petgraph;
extern crate ptree;
extern crate serde;
extern crate twox_hash;
#[macro_use]
extern crate log;
extern crate fern;
//#[macro_use]
extern crate flatbuffers;
extern crate snailquote;
extern crate structopt;

pub use self::gen::*;

// The generated code requires two tiers of outer modules so that references between
// modules resolve properly.
pub mod gen {
    pub mod proto {
        pub mod common {
            include!(concat!(env!("OUT_DIR"), "/common.rs"));
        }
        pub mod service {
            include!(concat!(env!("OUT_DIR"), "/service.rs"));
        }
        pub mod drivers {
            pub mod dxc {
                include!(concat!(env!("OUT_DIR"), "/drivers.dxc.rs"));
            }
            pub mod fxc {
                include!(concat!(env!("OUT_DIR"), "/drivers.fxc.rs"));
            }
            pub mod rga {
                include!(concat!(env!("OUT_DIR"), "/drivers.rga.rs"));
            }
            pub mod shaderc {
                include!(concat!(env!("OUT_DIR"), "/drivers.shaderc.rs"));
            }
            pub mod sign {
                include!(concat!(env!("OUT_DIR"), "/drivers.sign.rs"));
            }
            pub mod spirv_as {
                include!(concat!(env!("OUT_DIR"), "/drivers.spirv_as.rs"));
            }
            pub mod spirv_cross {
                include!(concat!(env!("OUT_DIR"), "/drivers.spirv_cross.rs"));
            }
            pub mod spirv_dis {
                include!(concat!(env!("OUT_DIR"), "/drivers.spirv_dis.rs"));
            }
        }
    }
}

pub mod client;
pub mod compile;
pub mod drivers;
pub mod error;
pub mod identity;
pub mod includes;
pub mod utilities;

pub use crate::error::{pretty_error, Error, ErrorKind, Result};
