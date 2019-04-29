#![windows_subsystem = "console"]

extern crate chashmap;
extern crate include_merkle;
extern crate scoped_threadpool;
extern crate serde;
extern crate svc_shader;
extern crate tower_http;
extern crate tower_util;
extern crate yansi;
#[macro_use]
extern crate log;
extern crate chrono;
extern crate elapsed;
extern crate fern;
extern crate flatbuffers;
#[cfg(target_os = "windows")]
extern crate hassle_rs;
extern crate smush;

use elapsed::ElapsedDuration;
#[cfg(target_os = "windows")]
use hassle_rs::Dxil;
use scoped_threadpool::Pool;
use snailquote::unescape;
use std::collections::hash_map::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use structopt::StructOpt;
use svc_shader::client::transport;
use svc_shader::compile::*;
use svc_shader::error::{Error, Result};
use svc_shader::proto::drivers;
use svc_shader::utilities::{path_exists, read_file};

use std::sync::atomic::{AtomicU32, Ordering};

mod generated;
use crate::generated::service::shader::schema;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

#[derive(StructOpt, Debug)]
#[structopt(name = "Shader Build")]
struct Options {
    /// Activate debug mode
    #[structopt(short = "x", long = "debug")]
    debug: bool,

    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbose: u8,

    /// Input manifest
    #[structopt(short = "i", long = "input", parse(from_os_str))]
    input: PathBuf,

    /// Output manifest
    #[structopt(short = "o", long = "output", parse(from_os_str))]
    output: Option<PathBuf>,

    /// Cache directory
    #[structopt(short = "c", long = "cache", parse(from_os_str))]
    cache: Option<PathBuf>,

    /// Base directory
    #[structopt(short = "b", long = "base", parse(from_os_str))]
    base: Option<PathBuf>,

    /// Embed data in output manifest
    #[structopt(short = "e", long = "embed")]
    embed: bool,

    /// Download artifacts to local cache
    #[structopt(short = "d", long = "download")]
    download: bool,

    /// Validate artifacts
    #[structopt(short = "a", long = "validate")]
    validate: bool,

    /// Validate artifacts (local)
    #[structopt(short = "l", long = "local-validate")]
    local_validate: bool,

    /// Stop on errors
    #[structopt(short = "s", long = "stop-errors")]
    stop_errors: bool,

    /// Service remote endpoint (defaults to 127.0.0.1:63999)
    #[structopt(short = "t", long = "endpoint")]
    endpoint: Option<String>,

    /// Windowing size
    #[structopt(short = "w", long = "window_size")]
    window_size: Option<u32>,

    /// Connection windowing size
    #[structopt(short = "n", long = "connection_window_size")]
    connection_window_size: Option<u32>,

    /// Parallel compilation
    #[structopt(short = "p", long = "parallel")]
    parallel: bool,
}

fn cache_hit(cache_path: &Path, identity: &str) -> bool {
    let data_path = cache_path.join(&identity);
    path_exists(&data_path)
}

fn cache_miss(cache_path: &Path, identity: &str) -> bool {
    !cache_hit(cache_path, identity)
}

fn cache_if_missing(cache_path: &Path, identity: &str, data: &[u8]) -> Result<()> {
    if cache_miss(cache_path, identity) {
        // These should match
        assert_eq!(include_merkle::compute_identity(&data), identity);
        let data_path = cache_path.join(&identity);
        let data_file = File::create(data_path)?;
        let mut data_writer = BufWriter::new(data_file);
        data_writer.write_all(data)?;
    }
    Ok(())
}

fn fetch_from_cache(cache_path: &Path, identity: &str) -> Result<Vec<u8>> {
    let data_path = cache_path.join(&identity);
    Ok(read_file(&data_path)?)
}

fn flatten_defines(defines: &Vec<(String, String)>) -> String {
    let mut define_list = String::new();
    for define in defines {
        if define.1.is_empty() {
            if define_list.is_empty() {
                define_list = format!("{}", define.0);
            } else {
                define_list = format!("{}, {}", define_list, define.0);
            }
        } else {
            if define_list.is_empty() {
                define_list = format!("{}={}", define.0, define.1);
            } else {
                define_list = format!("{}, {}={}", define_list, define.0, define.1);
            }
        }
    }
    define_list
}

#[repr(C)]
pub struct MinimalDxilHeader {
    four_cc: u32,
    hash_digest: [u32; 4],
}

const DXIL_HEADER_SIZE: usize = std::mem::size_of::<MinimalDxilHeader>();

pub fn get_dxil_digest(buffer: &[u8]) -> Result<[u32; 4]> {
    assert_eq!(DXIL_HEADER_SIZE, 20);
    if buffer.len() < DXIL_HEADER_SIZE {
        Err(Error::bug("invalid dxil header"))
    } else {
        let buffer_ptr: *const u8 = buffer.as_ptr();
        let header_ptr: *const MinimalDxilHeader = buffer_ptr as *const _;
        let header_ref: &MinimalDxilHeader = unsafe { &*header_ptr };
        let digest: [u32; 4] = [
            header_ref.hash_digest[0],
            header_ref.hash_digest[1],
            header_ref.hash_digest[2],
            header_ref.hash_digest[3],
        ];
        Ok(digest)
    }
}

pub fn has_dxil_digest(buffer: &[u8]) -> Result<bool> {
    let hash_digest = get_dxil_digest(buffer)?;
    let mut has_digest = false;
    has_digest |= hash_digest[0] != 0x0;
    has_digest |= hash_digest[1] != 0x0;
    has_digest |= hash_digest[2] != 0x0;
    has_digest |= hash_digest[3] != 0x0;
    Ok(has_digest)
}

pub fn zero_dxil_digest(buffer: &mut [u8]) -> Result<()> {
    assert_eq!(DXIL_HEADER_SIZE, 20);
    if buffer.len() < DXIL_HEADER_SIZE {
        Err(Error::bug("invalid dxil header"))
    } else {
        let buffer_ptr: *mut u8 = buffer.as_mut_ptr();
        let header_ptr: *mut MinimalDxilHeader = buffer_ptr as *mut _;
        let header_mut: &mut MinimalDxilHeader = unsafe { &mut *header_ptr };
        header_mut.hash_digest[0] = 0x0;
        header_mut.hash_digest[1] = 0x0;
        header_mut.hash_digest[2] = 0x0;
        header_mut.hash_digest[3] = 0x0;
        Ok(())
    }
}

fn main() {
    if let Err(err) = process() {
        let err = failure::Error::from(err);
        let mut count_context = 0;
        let mut _indent = " ".to_string();
        let causation = "".to_string();
        let separator = "---------------------------------------------------------".to_string();
        let mut message = "=========================================================\n".to_string();
        message.push_str(&format!(
            "Shader Build encountered an {}",
            yansi::Paint::red("error")
        ));
        message.push_str("\n");
        message.push_str(&separator);
        message.push_str("\n");
        message.push_str(&format!("{}", yansi::Paint::yellow(err.to_string())));
        message.push_str("\n");
        message.push_str(&separator);
        for cause in err.iter_causes() {
            message.push_str("\n");
            message.push_str(&_indent);
            _indent.push_str(&" ".to_string());
            message.push_str("▶ ");
            message.push_str(&causation);
            message.push_str(": ");
            message.push_str(&cause.to_string());
            count_context += 1;
        }
        if count_context != 0 {
            message.push_str("\n");
            //message.push_str(&separator);
        }

        error!("{}", message);
        std::process::exit(1);
    }
}

#[derive(Clone, Debug)]
struct ShaderArtifact {
    name: String,
    input: schema::InputFormat,
    output: schema::OutputFormat,
    identity: String,
    encoding: String,
    profile: schema::Profile,
    validated: bool,
}

#[derive(Clone, Default, Debug)]
struct ShaderRecord {
    name: String,
    entry: String,
    artifacts: Vec<ShaderArtifact>,
}

fn compile_hlsl_to_dxil(
    records: Arc<RwLock<Vec<ShaderRecord>>>,
    config: &transport::Config,
    cache_path: &Path,
    entry: &ParsedShaderEntry,
) -> Result<()> {
    if entry.language != "hlsl" {
        // Not an HLSL source file
        return Ok(());
    }

    if entry.output.iter().find(|name| name == &"dxil").is_none() {
        // DXIL output is not requested for this entry point
        return Ok(());
    }

    trace!(
        "Compiling '{}' [{}]: entry:[{}], file:[{:?}], DXIL, defines:{:#?}",
        entry.profile,
        entry.name,
        entry.entry_point,
        &cache_path.join(&entry.identity),
        &flatten_defines(&entry.defines),
    );

    let mut define_map: HashMap<String, String> = HashMap::new();
    entry.defines.iter().for_each(|(name, value)| {
        define_map.insert(name.to_string(), value.to_string());
    });

    let (target_profile, target_version) = parse_dxc_profile_version(entry.profile.as_ref());
    let options = drivers::dxc::CompileOptions {
        entry_point: entry.entry_point.clone(),
        definitions: define_map,
        input_format: drivers::dxc::InputFormat::Hlsl as i32,
        output_format: drivers::dxc::OutputFormat::Dxil as i32,
        target_version: target_version as i32,
        target_profile: target_profile as i32,
        optimization_level: drivers::dxc::OptimizationLevel::Two as i32,
        hlsl_version: drivers::dxc::HlslVersion::Edition2018 as i32,
        warning_level: drivers::dxc::WarningLevel::Default as i32,
        validation_level: drivers::dxc::ValidationLevel::Default as i32,
        code_generation: drivers::dxc::CodeGeneration::Enabled as i32,
        debug_info: drivers::dxc::DebugInfo::Enabled as i32,
        listing_info: drivers::dxc::ListingInfo::Enabled as i32,
        flow_control: drivers::dxc::FlowControl::Default as i32,
        denorm: drivers::dxc::DenormLevel::Any as i32,
        matrix_packing: drivers::dxc::MatrixPacking::Default as i32,
        signature_packing: drivers::dxc::SignaturePacking::PrefixStable as i32,
        all_resources_bound: false,
        enable_16bit_types: false,
        legacy_macro_expansion: false,
        color_coded_listing: true,
        strict_mode: false,
        force_ieee: false,
        output_include_depth: false,
        output_include_details: false,
        output_hex_literals: false,
        output_instruction_numbers: false,
        output_instruction_offsets: false,
        output_optimizer_commands: false,
        ignore_line_directives: false,
        deny_legacy_cbuffer_load: true,
        spirv: None,
    };

    let mut record = ShaderRecord {
        name: entry.name.to_owned(),
        entry: entry.entry_point.clone(),
        artifacts: Vec::new(),
    };

    let artifact_profile = match target_profile {
        drivers::dxc::TargetProfile::Pixel => schema::Profile::Pixel,
        drivers::dxc::TargetProfile::Vertex => schema::Profile::Vertex,
        drivers::dxc::TargetProfile::Compute => schema::Profile::Compute,
        drivers::dxc::TargetProfile::Geometry => schema::Profile::Geometry,
        drivers::dxc::TargetProfile::Domain => schema::Profile::Domain,
        drivers::dxc::TargetProfile::Hull => schema::Profile::Hull,
        drivers::dxc::TargetProfile::RayGen => schema::Profile::RayGen,
        drivers::dxc::TargetProfile::RayIntersection => schema::Profile::RayIntersection,
        drivers::dxc::TargetProfile::RayClosestHit => schema::Profile::RayClosestHit,
        drivers::dxc::TargetProfile::RayAnyHit => schema::Profile::RayAnyHit,
        drivers::dxc::TargetProfile::RayMiss => schema::Profile::RayMiss,
    };

    let results = transport::compile_dxc(&config, &entry.identity, options)?;
    for result in &results {
        let output_identity = if let Some(ref identity) = &result.identity {
            identity.sha256_base58.clone()
        } else {
            String::new()
        };
        trace!(
            "   DXC output received - identity:{}, name:{}",
            output_identity,
            result.name
        );
        if !result.output.is_empty() {
            trace!("Output:\n{}", result.output);
        }
        if !result.errors.is_empty() {
            let errors = unescape(&result.errors).unwrap();
            for error in errors.lines() {
                error!("{}", error);
            }
            return Err(Error::process("Compilation failed due to errors"));
        }

        if result.name == "Code" {
            record.artifacts.push(ShaderArtifact {
                name: result.name.to_owned(),
                input: schema::InputFormat::Hlsl,
                output: schema::OutputFormat::Dxil,
                identity: output_identity.to_owned(),
                encoding: String::from("identity"),
                profile: artifact_profile,
                validated: false,
            });
        } else if result.name == "Listing" {
            record.artifacts.push(ShaderArtifact {
                name: result.name.to_owned(),
                input: schema::InputFormat::Hlsl,
                output: schema::OutputFormat::Text,
                identity: output_identity.to_owned(),
                encoding: String::from("identity"),
                profile: artifact_profile,
                validated: false,
            });
        } else if result.name == "Debug" {
            record.artifacts.push(ShaderArtifact {
                name: result.name.to_owned(),
                input: schema::InputFormat::Hlsl,
                output: schema::OutputFormat::Blob,
                identity: output_identity.to_owned(),
                encoding: String::from("identity"),
                profile: artifact_profile,
                validated: false,
            });
        }
    }

    let mut records = records.write().unwrap();
    records.push(record);
    Ok(())
}

fn compile_hlsl_to_spirv(
    records: Arc<RwLock<Vec<ShaderRecord>>>,
    config: &transport::Config,
    cache_path: &Path,
    entry: &ParsedShaderEntry,
) -> Result<()> {
    if entry.language != "hlsl" {
        // Not an HLSL source file
        return Ok(());
    }

    if entry.output.iter().find(|name| name == &"spirv").is_none() {
        // SPIR-V output is not requested for this entry point
        return Ok(());
    }

    trace!(
        "Compiling '{}' [{}]: entry:[{}], file:[{:?}], SPIR-V, defines:{:#?}",
        entry.profile,
        entry.name,
        entry.entry_point,
        &cache_path.join(&entry.identity),
        &flatten_defines(&entry.defines),
    );

    let mut define_map: HashMap<String, String> = HashMap::new();
    entry.defines.iter().for_each(|(name, value)| {
        define_map.insert(name.to_string(), value.to_string());
    });

    let (target_profile, target_version) = parse_dxc_profile_version(entry.profile.as_ref());
    let options = drivers::dxc::CompileOptions {
        entry_point: entry.entry_point.clone(),
        definitions: define_map,
        input_format: drivers::dxc::InputFormat::Hlsl as i32,
        output_format: drivers::dxc::OutputFormat::Spirv as i32,
        target_version: target_version as i32,
        target_profile: target_profile as i32,
        optimization_level: drivers::dxc::OptimizationLevel::Two as i32,
        hlsl_version: drivers::dxc::HlslVersion::Edition2018 as i32,
        warning_level: drivers::dxc::WarningLevel::Default as i32,
        validation_level: drivers::dxc::ValidationLevel::Default as i32,
        code_generation: drivers::dxc::CodeGeneration::Enabled as i32,
        debug_info: drivers::dxc::DebugInfo::Enabled as i32,
        listing_info: drivers::dxc::ListingInfo::Enabled as i32,
        flow_control: drivers::dxc::FlowControl::Default as i32,
        denorm: drivers::dxc::DenormLevel::Any as i32,
        matrix_packing: drivers::dxc::MatrixPacking::Default as i32,
        signature_packing: drivers::dxc::SignaturePacking::PrefixStable as i32,
        all_resources_bound: false,
        enable_16bit_types: false,
        legacy_macro_expansion: false,
        color_coded_listing: true,
        strict_mode: false,
        force_ieee: false,
        output_include_depth: false,
        output_include_details: false,
        output_hex_literals: false,
        output_instruction_numbers: false,
        output_instruction_offsets: false,
        output_optimizer_commands: false,
        ignore_line_directives: false,
        deny_legacy_cbuffer_load: true,
        spirv: Some(drivers::dxc::CompileOptionsSpirv {
            version: drivers::dxc::VulkanVersion::Vulkan11 as i32,
            emit_reflection: true,
            dx_position_w: false,
            invert_y: false,
            resource_layout: drivers::dxc::VulkanResourceLayout::Dx as i32,
            binding_shifts: Vec::new(), // TODO: Make configurable
            /*
            binding_shifts: vec![
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::B as i32,
                    shift: 0,
                    space: 0,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::S as i32,
                    shift: 1000,
                    space: 0,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::T as i32,
                    shift: 2000,
                    space: 0,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::U as i32,
                    shift: 3000,
                    space: 0,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::B as i32,
                    shift: 0,
                    space: 1,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::S as i32,
                    shift: 1000,
                    space: 1,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::T as i32,
                    shift: 2000,
                    space: 1,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::U as i32,
                    shift: 3000,
                    space: 1,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::B as i32,
                    shift: 0,
                    space: 2,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::S as i32,
                    shift: 1000,
                    space: 2,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::T as i32,
                    shift: 2000,
                    space: 2,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::U as i32,
                    shift: 3000,
                    space: 2,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::B as i32,
                    shift: 0,
                    space: 3,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::S as i32,
                    shift: 1000,
                    space: 3,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::T as i32,
                    shift: 2000,
                    space: 3,
                },
                drivers::dxc::VulkanBindingShift {
                    binding_type: drivers::dxc::VulkanBindingType::U as i32,
                    shift: 3000,
                    space: 3,
                },
            ],
            */
            binding_registers: Vec::new(),
            opt_config: Vec::new(),
            debug_info: Vec::new(),
            extensions: Vec::new(),
        }),
    };

    let mut record = ShaderRecord {
        name: entry.name.to_owned(),
        entry: entry.entry_point.clone(),
        artifacts: Vec::new(),
    };

    let artifact_profile = match target_profile {
        drivers::dxc::TargetProfile::Pixel => schema::Profile::Pixel,
        drivers::dxc::TargetProfile::Vertex => schema::Profile::Vertex,
        drivers::dxc::TargetProfile::Compute => schema::Profile::Compute,
        drivers::dxc::TargetProfile::Geometry => schema::Profile::Geometry,
        drivers::dxc::TargetProfile::Domain => schema::Profile::Domain,
        drivers::dxc::TargetProfile::Hull => schema::Profile::Hull,
        drivers::dxc::TargetProfile::RayGen => schema::Profile::RayGen,
        drivers::dxc::TargetProfile::RayIntersection => schema::Profile::RayIntersection,
        drivers::dxc::TargetProfile::RayClosestHit => schema::Profile::RayClosestHit,
        drivers::dxc::TargetProfile::RayAnyHit => schema::Profile::RayAnyHit,
        drivers::dxc::TargetProfile::RayMiss => schema::Profile::RayMiss,
    };

    let results = transport::compile_dxc(&config, &entry.identity, options)?;
    for result in &results {
        let output_identity = if let Some(ref identity) = &result.identity {
            identity.sha256_base58.clone()
        } else {
            String::new()
        };
        trace!(
            "   DXC output received - identity:{}, name:{}",
            output_identity,
            result.name
        );
        if !result.output.is_empty() {
            trace!("Output:\n{}", result.output);
        }
        if !result.errors.is_empty() {
            let errors = unescape(&result.errors).unwrap();
            for error in errors.lines() {
                error!("{}", error);
            }
            return Err(Error::process("Compilation failed due to errors"));
        }

        if result.name == "Code" {
            record.artifacts.push(ShaderArtifact {
                name: result.name.to_owned(),
                input: schema::InputFormat::Hlsl,
                output: schema::OutputFormat::Spirv,
                identity: output_identity.to_owned(),
                encoding: String::from("identity"),
                profile: artifact_profile,
                validated: false,
            });
        } else if result.name == "Listing" {
            record.artifacts.push(ShaderArtifact {
                name: result.name.to_owned(),
                input: schema::InputFormat::Hlsl,
                output: schema::OutputFormat::Text,
                identity: output_identity.to_owned(),
                encoding: String::from("identity"),
                profile: artifact_profile,
                validated: false,
            });
        }
    }

    let mut records = records.write().unwrap();
    records.push(record);
    Ok(())
}

fn compile_glsl_to_spirv(
    records: Arc<RwLock<Vec<ShaderRecord>>>,
    config: &transport::Config,
    cache_path: &Path,
    entry: &ParsedShaderEntry,
) -> Result<()> {
    if entry.language != "glsl" {
        // Not a GLSL source file
        return Ok(());
    }

    if entry.output.iter().find(|name| name == &"spirv").is_none() {
        // SPIR-V output is not requested for this entry point
        return Ok(());
    }

    trace!(
        "Compiling '{}' [{}]: entry:[{}], file:[{:?}], SPIR-V, defines:{:?}",
        entry.profile,
        entry.name,
        entry.entry_point,
        &cache_path.join(&entry.identity),
        &flatten_defines(&entry.defines),
    );

    let mut define_map: HashMap<String, String> = HashMap::new();
    entry.defines.iter().for_each(|(name, value)| {
        define_map.insert(name.to_string(), value.to_string());
    });

    let (target_profile, vulkan_version) = parse_glslc_profile_version(entry.profile.as_ref());
    let options = drivers::shaderc::CompileOptions {
        entry_point: entry.entry_point.clone(),
        definitions: define_map,
        input_format: drivers::shaderc::InputFormat::Glsl as i32,
        output_format: drivers::shaderc::OutputFormat::Spirv as i32,
        target_profile: target_profile as i32,
        version: vulkan_version as i32,
        optimization_level: drivers::shaderc::OptimizationLevel::Perf as i32,
        warning_level: drivers::shaderc::WarningLevel::Default as i32,
        debug_info: drivers::shaderc::DebugInfo::Enabled as i32,
        auto_bind_uniforms: true,
        auto_map_locations: true,
        hlsl_functionality1: true,
        hlsl_iomap: true,
        hlsl_offsets: true,
        std: String::new(),
        binding_bases: Vec::new(),
        binding_stage_bases: Vec::new(),
        register_bases: Vec::new(),
        register_stage_bases: Vec::new(),
    };

    let mut record = ShaderRecord {
        name: entry.name.to_owned(),
        entry: entry.entry_point.clone(),
        artifacts: Vec::new(),
    };

    let artifact_profile = match target_profile {
        drivers::shaderc::TargetProfile::Pixel => schema::Profile::Pixel,
        drivers::shaderc::TargetProfile::Vertex => schema::Profile::Vertex,
        drivers::shaderc::TargetProfile::Compute => schema::Profile::Compute,
        drivers::shaderc::TargetProfile::Geometry => schema::Profile::Geometry,
        drivers::shaderc::TargetProfile::Domain => schema::Profile::Domain,
        drivers::shaderc::TargetProfile::Hull => schema::Profile::Hull,
        drivers::shaderc::TargetProfile::Task => schema::Profile::Task,
        drivers::shaderc::TargetProfile::Mesh => schema::Profile::Mesh,
        drivers::shaderc::TargetProfile::RayGen => schema::Profile::RayGen,
        drivers::shaderc::TargetProfile::RayIntersection => schema::Profile::RayIntersection,
        drivers::shaderc::TargetProfile::RayClosestHit => schema::Profile::RayClosestHit,
        drivers::shaderc::TargetProfile::RayAnyHit => schema::Profile::RayAnyHit,
        drivers::shaderc::TargetProfile::RayMiss => schema::Profile::RayMiss,
    };

    let results = transport::compile_glslc(&config, &entry.identity, options)?;
    for result in &results {
        let output_identity = if let Some(ref identity) = &result.identity {
            identity.sha256_base58.clone()
        } else {
            String::new()
        };
        trace!(
            "   GLSLC output received - identity:{}, name:{}",
            output_identity,
            result.name
        );
        if !result.output.is_empty() {
            trace!("Output:\n{}", result.output);
        }
        if !result.errors.is_empty() {
            let errors = unescape(&result.errors).unwrap();
            for error in errors.lines() {
                error!("{}", error);
            }
            return Err(Error::process("Compilation failed due to errors"));
        }

        if result.name == "Code" {
            record.artifacts.push(ShaderArtifact {
                name: result.name.to_owned(),
                input: schema::InputFormat::Glsl,
                output: schema::OutputFormat::Spirv,
                identity: output_identity.to_owned(),
                encoding: String::from("identity"),
                profile: artifact_profile,
                validated: false,
            });
        }
    }

    let mut records = records.write().unwrap();
    records.push(record);
    Ok(())
}

#[cfg(target_os = "windows")]
fn local_validate_artifacts(cache_path: &Path, records: &mut Vec<ShaderRecord>) -> Result<()> {
    use svc_shader::utilities::compute_identity;

    let dxil = Dxil::new();
    let validator = dxil.create_validator();

    match validator {
        Ok(mut validator) => {
            let version = validator.version().unwrap_or_else(|_| (0, 0));
            info!("DXIL validation version: {}.{}", version.0, version.1);
            for record in &mut *records {
                for artifact in &mut record.artifacts {
                    if !artifact.validated {
                        match artifact.output {
                            schema::OutputFormat::Dxil => {
                                // Artifact with unsigned DXIL
                                let unsigned_identity = artifact.identity.to_owned();
                                trace!("Signing DXIL: {}", &unsigned_identity);
                                let mut input_data =
                                    fetch_from_cache(cache_path, &unsigned_identity)?;
                                zero_dxil_digest(&mut input_data)?;
                                match validator.validate_slice(&input_data) {
                                    Ok((output_data, errors)) => {
                                        if errors.is_empty() {
                                            // Make sure the DXIL is now signed
                                            if has_dxil_digest(&output_data)
                                                .unwrap_or_else(|_| false)
                                            {
                                                trace!(
                                                    "  DXIL is now signed - digest: {:?}",
                                                    get_dxil_digest(&output_data)?
                                                );
                                            } else {
                                                return Err(Error::bug(format!(
                                                    "validation failed - data is not signed",
                                                )));
                                            }

                                            artifact.identity = compute_identity(&output_data);
                                            cache_if_missing(
                                                cache_path,
                                                &artifact.identity,
                                                &output_data,
                                            )?;
                                            artifact.validated = true;
                                        } else {
                                            return Err(Error::bug(format!(
                                                "validation failed - {:}",
                                                errors
                                            )));
                                        }
                                    }
                                    Err(err) => {
                                        return Err(Error::bug(format!(
                                            "error validating DXIL - {:?}",
                                            err
                                        )));
                                    }
                                }
                            }
                            schema::OutputFormat::Spirv => {
                                // Artifact with SPIR-V - run spirv-val?
                                // https://vulkan.lunarg.com/doc/view/1.1.92.1/linux/spirv_toolchain.html
                            }
                            _ => {}
                        }
                    }
                }
            }

            Ok(())
        }
        Err(err) => Err(Error::bug(format!(
            "error creating DXIL validator - {:?}",
            err
        ))),
    }
}

#[cfg(not(target_os = "windows"))]
fn local_validate_artifacts(_cache_path: &Path, _records: &mut Vec<ShaderRecord>) -> Result<()> {
    Ok(())
}

fn validate_artifact(artifact: &mut ShaderArtifact, config: &transport::Config) -> Result<()> {
    if !artifact.validated {
        match artifact.output {
            schema::OutputFormat::Dxil => {
                // Artifact with unsigned DXIL
                let unsigned_identity = artifact.identity.to_owned();
                info!("Signing DXIL: {}", &unsigned_identity);
                let signed_results = transport::sign_dxil(&config, &unsigned_identity)?;
                if signed_results.len() != 1 {
                    return Err(Error::bug("failed to sign dxil - invalid results"));
                }

                let signed_result = &signed_results[0];
                artifact.validated = true;
                artifact.identity = if let Some(ref identity) = &signed_result.identity {
                    identity.sha256_base58.clone()
                } else {
                    return Err(Error::bug(format!(
                        "failed to sign dxil - {}",
                        signed_result.errors
                    )));
                };
            }
            schema::OutputFormat::Spirv => {
                // Artifact with SPIR-V - run spirv-val?
                // https://vulkan.lunarg.com/doc/view/1.1.92.1/linux/spirv_toolchain.html
            }
            _ => {}
        }
    }

    Ok(())
}

fn process() -> Result<()> {
    let time_total_start = Instant::now();

    std::env::set_var("RUST_BACKTRACE", "1");

    let process_opt = Options::from_args();

    let verbosity = if process_opt.debug { 1 } else { 0 };
    setup_logging(verbosity).expect("failed to initialize logging.");

    info!(
        "Shader Build v{} starting up!",
        VERSION.unwrap_or("UNKNOWN")
    );
    debug!("{:?}", process_opt);

    let base_path = match process_opt.base {
        Some(ref base_path) => base_path,
        None => Path::new("./"),
    };

    let cache_path = match process_opt.cache {
        Some(ref cache_path) => cache_path,
        None => Path::new("./.cache"),
    };

    std::fs::create_dir_all(cache_path)?;

    let config = transport::Config {
        address: if let Some(ref endpoint) = process_opt.endpoint {
            endpoint.to_owned()
        } else {
            "127.0.0.1:63999".to_string()
        },
        window_size: process_opt.window_size,
        connection_window_size: process_opt.connection_window_size,
    };

    let mut thread_pool = Pool::new(8);

    info!(
        "Loading shader manifest: {:?}",
        &process_opt.input.as_path()
    );

    // Load shader manifest from toml path
    let time_manifest_start = Instant::now();
    let manifest = load_manifest(&base_path, &process_opt.input.as_path())?;
    let time_manifest_elapsed = ElapsedDuration::new(time_manifest_start.elapsed());

    let mut merkle_entries: Vec<ParsedShaderEntry> = Vec::with_capacity(manifest.entries.len());
    let mut active_identities: Vec<String> = Vec::with_capacity(manifest.entries.len() * 16);

    info!("Generate merkle identity tree of shader files");
    let time_merkle_start = Instant::now();

    for ShaderEntry {
        ref name,
        ref profile,
        ref entry_point,
        ref entry_file,
        ref output,
        ref defines,
    } in &manifest.entries
    {
        let full_path = base_path.join(&entry_file);
        let canonical_path = full_path
            .canonicalize()
            //.with_context(|_| ErrorKind::path(&full_path))
            .unwrap(); //?;
        let file_extension = match canonical_path.extension() {
            Some(ref extension) => extension.to_string_lossy().into_owned(),
            None => String::new(),
        };
        let mut entry_graph = include_merkle::IncludeNodeGraph::new();
        let entry_node = include_merkle::traverse_build(
            &mut entry_graph,
            &base_path,
            &canonical_path,
            0,
            true, /* normalize endings */
        );
        include_merkle::traverse_patch(
            &mut entry_graph,
            entry_node,
            true, /* normalize endings */
        );
        include_merkle::graph_to_node_vec(&entry_graph)
            .iter()
            .for_each(|node| {
                let patched_data = node.flattened.as_bytes();
                let patched_identity = include_merkle::compute_identity(&patched_data);
                trace!(
                    "Patched identity: {:?}",
                    &cache_path.join(&patched_identity)
                );
                cache_if_missing(cache_path, &patched_identity, &patched_data).unwrap();
                active_identities.push(patched_identity);
            });
        if let Some(ref node) = include_merkle::get_root_node(&entry_graph) {
            let patched_identity = match node.patched_identity {
                Some(ref identity) => &identity,
                None => "INVALID",
            };
            trace!("Entry point: {:?}", &cache_path.join(&patched_identity));
            let defines = match defines {
                Some(ref defines) => defines
                    .iter()
                    .map(|define| {
                        let define_parts = define.split('=').collect::<Vec<&str>>();
                        if define_parts.len() == 2 {
                            (define_parts[0].to_string(), define_parts[1].to_string())
                        } else if define_parts.len() == 1 {
                            (define_parts[0].to_string(), String::new())
                        } else {
                            println!("Invalid define: {:?}", define);
                            (String::new(), String::new())
                        }
                    })
                    .collect::<Vec<(String, String)>>(),
                None => Vec::new(),
            };
            merkle_entries.push(ParsedShaderEntry {
                name: name.to_string(),
                profile: profile.to_string(),
                entry_point: entry_point.to_string(),
                identity: patched_identity.to_string(),
                output: output.clone(),
                language: file_extension,
                defines,
            });
        } else {
            unimplemented!();
        }

        trace!("\n{}", include_merkle::graph_to_dot(&entry_graph));
        let show_merkle = false;
        if show_merkle {
            include_merkle::graph_to_stdout(&entry_graph, entry_node).unwrap();
        }
    }

    // Remove multiple references to the same file (for efficiency).
    active_identities.sort_by(|a, b| a.cmp(&b));
    active_identities.dedup_by(|a, b| a.eq(&b));

    let time_merkle_elapsed = ElapsedDuration::new(time_merkle_start.elapsed());

    // Query what identities are missing from the remote endpoint.
    info!("Querying missing identities from remote endpoint");
    let time_query_start = Instant::now();
    let missing_identities = transport::query_missing_identities(&config, &active_identities)?;
    let time_query_elapsed = ElapsedDuration::new(time_query_start.elapsed());

    // Upload missing identities to the remote endpoint.
    let time_upload_start = Instant::now();
    if process_opt.parallel {
        thread_pool.scoped(|scoped| {
            for missing_identity in &missing_identities {
                let config = config.clone();
                scoped.execute(move || {
                    info!("Uploading missing identity: {}", missing_identity);
                    let identity_data = fetch_from_cache(cache_path, &missing_identity).unwrap(); //?;
                    let uploaded_identity =
                        transport::upload_identity(&config, &missing_identity, &identity_data)
                            .unwrap(); //?;
                    assert_eq!(missing_identity, &uploaded_identity);
                });
            }
        });
    } else {
        for missing_identity in &missing_identities {
            trace!("Uploading missing identity: {}", missing_identity);
            let identity_data = fetch_from_cache(cache_path, &missing_identity)?;
            let uploaded_identity =
                transport::upload_identity(&config, &missing_identity, &identity_data)?;
            assert_eq!(missing_identity, &uploaded_identity);
        }
    }
    let time_upload_elapsed = ElapsedDuration::new(time_upload_start.elapsed());

    let records: Arc<RwLock<Vec<ShaderRecord>>> = Arc::new(RwLock::new(Vec::new()));
    let error_count = Arc::new(AtomicU32::new(0));

    // Compile HLSL -> DXIL
    info!("Compiling HLSL -> DXIL");
    let time_hlsl_to_dxil_start = Instant::now();

    if process_opt.parallel {
        thread_pool.scoped(|scoped| {
            for entry in &merkle_entries {
                let config = config.clone();
                let records = records.clone();
                let error_count = error_count.clone();
                scoped.execute(move || {
                    if let Err(_) = compile_hlsl_to_dxil(records, &config, &cache_path, entry) {
                        error!(
                            "Failed to compile: '{}' [{}]: entry:[{}], file:[{:?}], DXIL, defines:{:#?}",
                            entry.profile,
                            entry.name,
                            entry.entry_point,
                            &cache_path.join(&entry.identity),
                            &flatten_defines(&entry.defines),
                        );
                        error_count.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
    } else {
        let records = records.clone();
        for entry in &merkle_entries {
            if let Err(_) = compile_hlsl_to_dxil(records.clone(), &config, &cache_path, entry) {
                error!(
                    "Failed to compile: '{}' [{}]: entry:[{}], file:[{:?}], DXIL, defines:{:#?}",
                    entry.profile,
                    entry.name,
                    entry.entry_point,
                    &cache_path.join(&entry.identity),
                    &flatten_defines(&entry.defines),
                );
                error_count.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    println!("Error count: {:?}", error_count);

    let time_hlsl_to_dxil_elapsed = ElapsedDuration::new(time_hlsl_to_dxil_start.elapsed());

    // Compile HLSL -> SPIR-V
    info!("Compiling HLSL -> SPIR-V");
    let time_hlsl_to_spirv_start = Instant::now();
    if process_opt.parallel {
        thread_pool.scoped(|scoped| {
            for entry in &merkle_entries {
                let config = config.clone();
                let records = records.clone();
                let error_count = error_count.clone();
                scoped.execute(move || {
                    if let Err(_) = compile_hlsl_to_spirv(records, &config, &cache_path, entry) {
                        error_count.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
    } else {
        let records = records.clone();
        for entry in &merkle_entries {
            if let Err(_) = compile_hlsl_to_spirv(records.clone(), &config, &cache_path, entry) {
                error_count.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    let time_hlsl_to_spirv_elapsed = ElapsedDuration::new(time_hlsl_to_spirv_start.elapsed());

    // Compile GLSL -> SPIR-V
    info!("Compiling GLSL -> SPIR-V");
    let time_glsl_to_spirv_start = Instant::now();
    if process_opt.parallel {
        thread_pool.scoped(|scoped| {
            for entry in &merkle_entries {
                let config = config.clone();
                let records = records.clone();
                let error_count = error_count.clone();
                scoped.execute(move || {
                    if let Err(_) = compile_glsl_to_spirv(records, &config, &cache_path, entry) {
                        error_count.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
    } else {
        let records = records.clone();
        for entry in &merkle_entries {
            if let Err(_) = compile_glsl_to_spirv(records.clone(), &config, &cache_path, entry) {
                error_count.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    let time_glsl_to_spirv_elapsed = ElapsedDuration::new(time_glsl_to_spirv_start.elapsed());

    let time_validate_start = Instant::now();
    if process_opt.validate {
        info!("Validating shader artifacts");
        let mut records = records.write().unwrap();
        if process_opt.parallel {
            thread_pool.scoped(|scoped| {
                for record in &mut *records {
                    let config = config.clone();
                    let error_count = error_count.clone();
                    scoped.execute(move || {
                        for artifact in &mut record.artifacts {
                            if let Err(_) = validate_artifact(artifact, &config) {
                                error_count.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    });
                }
            });
        } else {
            for record in &mut *records {
                for artifact in &mut record.artifacts {
                    if let Err(_) = validate_artifact(artifact, &config) {
                        error_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
    }
    let time_validate_elapsed = ElapsedDuration::new(time_validate_start.elapsed());

    let time_download_start = Instant::now();
    if process_opt.download
        || process_opt.local_validate
        || (process_opt.output.is_some() && process_opt.embed)
    {
        info!("Downloading shader artifacts to local cache");
        let records = records.read().unwrap();
        for record in &*records {
            if !record.artifacts.is_empty() {
                debug!("Artifacts:[{}] - Entry:[{}]", record.name, record.entry);
            }
            for artifact in &record.artifacts {
                let input_name = match artifact.input {
                    schema::InputFormat::Hlsl => "HLSL",
                    schema::InputFormat::Glsl => "GLSL",
                };

                let output_name = match artifact.output {
                    schema::OutputFormat::Blob => "BLOB",
                    schema::OutputFormat::Dxil => {
                        if artifact.validated {
                            "DXIL (Signed)"
                        } else {
                            "DXIL"
                        }
                    }
                    schema::OutputFormat::Smolv => "SMOL-V",
                    schema::OutputFormat::Spirv => {
                        if artifact.validated {
                            "SPIR-V (Validated)"
                        } else {
                            "SPIR-V"
                        }
                    }
                    schema::OutputFormat::Text => "TEXT",
                };

                let identity_path = cache_path.join(&artifact.identity);

                if cache_miss(cache_path, &artifact.identity) {
                    let remote_data = transport::download_identity(&config, &artifact.identity)?;
                    cache_if_missing(cache_path, &artifact.identity, &remote_data)?;
                    debug!(
                        "  {} -> {} '{}' [Cache Miss]: {:?}",
                        input_name, output_name, artifact.name, identity_path
                    );
                } else {
                    debug!(
                        "  {} -> {} '{}' [Cache Hit]: {:?}",
                        input_name, output_name, artifact.name, identity_path
                    );
                }
            }
        }
    }
    let time_download_elapsed = ElapsedDuration::new(time_download_start.elapsed());

    let time_local_validate_start = Instant::now();
    if process_opt.local_validate {
        info!("Validating shader artifacts (local)");
        let mut records = records.write().unwrap();
        local_validate_artifacts(&cache_path, &mut records)?;
    }
    let time_local_validate_elapsed = ElapsedDuration::new(time_local_validate_start.elapsed());

    // Retrieve final error count
    let error_count = error_count.load(Ordering::SeqCst);
    if error_count > 0 {
        Err(Error::process(format!(
            "Shader compilation failed - {} errors",
            error_count
        )))
    } else {
        let time_archive_start = Instant::now();
        if let Some(ref output_path) = process_opt.output {
            info!("Generating shader manifest archive");
            let records = records.read().unwrap();
            let mut manifest_builder = flatbuffers::FlatBufferBuilder::new();
            let manifest_shaders: Vec<_> = records
                .iter()
                .map(|shader| {
                    let name = Some(manifest_builder.create_string(&shader.name));
                    let entry = Some(manifest_builder.create_string(&shader.entry));
                    let artifacts: Vec<_> = shader
                        .artifacts
                        .iter()
                        .map(|artifact| {
                            let name = Some(manifest_builder.create_string(&artifact.name));
                            let identity = Some(manifest_builder.create_string(&artifact.identity));
                            let encoding = Some(manifest_builder.create_string(&artifact.encoding));
                            let data = if process_opt.embed {
                                let data = fetch_from_cache(cache_path, &artifact.identity)
                                    .expect("failed to fetch from cache");
                                Some(manifest_builder.create_vector(&data))
                            } else {
                                None
                            };
                            schema::Artifact::create(
                                &mut manifest_builder,
                                &schema::ArtifactArgs {
                                    name,
                                    input: artifact.input,
                                    output: artifact.output,
                                    identity,
                                    encoding,
                                    profile: artifact.profile,
                                    validated: artifact.validated,
                                    data,
                                },
                            )
                        })
                        .collect();
                    let artifacts = Some(manifest_builder.create_vector(&artifacts));
                    schema::Shader::create(
                        &mut manifest_builder,
                        &schema::ShaderArgs {
                            name,
                            entry,
                            artifacts,
                        },
                    )
                })
                .collect();

            let manifest_shaders = Some(manifest_builder.create_vector(&manifest_shaders));
            let manifest = schema::Manifest::create(
                &mut manifest_builder,
                &schema::ManifestArgs {
                    shaders: manifest_shaders,
                },
            );

            manifest_builder.finish(manifest, None);
            let manifest_data = manifest_builder.finished_data();

            info!("Saving shader manifest archive: {:?}", &output_path);
            let manifest_file = File::create(output_path)?;
            let mut manifest_writer = BufWriter::new(manifest_file);
            manifest_writer.write_all(&manifest_data)?;
        }
        let time_archive_elapsed = ElapsedDuration::new(time_archive_start.elapsed());
        let time_total_elapsed = ElapsedDuration::new(time_total_start.elapsed());

        info!("Shader compilation succeeded");
        let timings = true;
        if timings {
            println!("Timings (total: {}):", time_total_elapsed);
            println!("  Load Manifest: {}", time_manifest_elapsed);
            println!("  Merkle Build: {}", time_merkle_elapsed);
            println!("  Query Missing: {}", time_query_elapsed);
            println!("  Upload Missing: {}", time_upload_elapsed);
            println!("  HLSL to DXIL: {}", time_hlsl_to_dxil_elapsed);
            println!("  HLSL to SPIR-V: {}", time_hlsl_to_spirv_elapsed);
            println!("  GLSL to SPIR-V: {}", time_glsl_to_spirv_elapsed);
            println!("  Remote Validation: {}", time_validate_elapsed);
            println!("  Local Validation: {}", time_local_validate_elapsed);
            println!("  Download Artifacts: {}", time_download_elapsed);
            println!("  Export Artifacts: {}", time_archive_elapsed);
        }

        Ok(())
    }
}

fn setup_logging(verbosity: u64) -> Result<()> {
    std::fs::create_dir_all(Path::new("./logs"))?;

    let mut base_config = fern::Dispatch::new();
    base_config = match verbosity {
        0 => {
            // Let's say we depend on something which whose "info" level messages are too
            // verbose to include in end-user output. If we don't need them,
            // let's not include them.
            base_config
                .level(log::LevelFilter::Info)
                .level_for("overly-verbose-target", log::LevelFilter::Warn)
                .level_for("tokio_core", log::LevelFilter::Warn)
                .level_for("tokio_reactor", log::LevelFilter::Warn)
                .level_for("httpbis", log::LevelFilter::Warn)
        }
        1 => base_config
            .level(log::LevelFilter::Debug)
            .level_for("overly-verbose-target", log::LevelFilter::Info)
            .level_for("tokio_core", log::LevelFilter::Warn)
            .level_for("tokio_reactor", log::LevelFilter::Warn)
            .level_for("h2", log::LevelFilter::Warn)
            .level_for("httpbis", log::LevelFilter::Warn),
        2 => base_config.level(log::LevelFilter::Debug),
        _3_or_more => base_config.level(log::LevelFilter::Trace),
    };

    // Separate file config so we can include year, month and day in file logs
    let file_config = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .chain(
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                //.append(true)
                .truncate(true)
                .open("logs/compile.log")?,
        );

    let stdout_config = fern::Dispatch::new()
        .format(|out, message, record| {
            // special format for debug messages coming from our own crate.
            if record.level() > log::LevelFilter::Info && record.target() == "shader_build" {
                out.finish(format_args!(
                    "---\nDEBUG: {}: {}\n---",
                    chrono::Local::now().format("%H:%M:%S"),
                    message
                ))
            } else {
                out.finish(format_args!(
                    "[{}][{}][{}] {}",
                    chrono::Local::now().format("%H:%M"),
                    record.target(),
                    record.level(),
                    message
                ))
            }
        })
        .chain(::std::io::stdout());

    base_config
        .chain(file_config)
        .chain(stdout_config)
        .apply()
        .unwrap();

    //jobs::enqueue_shader_work(&base_path, &manifest.entries, 8);

    Ok(())
}
