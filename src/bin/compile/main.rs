extern crate base58;
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
extern crate fern;
extern crate flatbuffers;

use std::collections::hash_map::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::path::PathBuf;
use structopt::StructOpt;
use svc_shader::client::transport;
use svc_shader::compile::*;
use svc_shader::encoding::{decode_data, encode_data, Encoding};
use svc_shader::error::{Error, Result};
use svc_shader::proto::drivers;
use svc_shader::utilities::{self, path_exists, read_file};

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

    /// Service remote endpoint (defaults to 127.0.0.1:63999)
    #[structopt(short = "e", long = "endpoint")]
    endpoint: Option<String>,

    /// Windowing size
    #[structopt(short = "w", long = "window_size")]
    window_size: Option<u32>,

    /// Connection windowing size
    #[structopt(short = "n", long = "connection_window_size")]
    connection_window_size: Option<u32>,
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

#[allow(clippy::cyclomatic_complexity)]
fn process() -> Result<()> {
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

    // Load shader manifest from toml path
    let manifest = load_manifest(&base_path, &process_opt.input.as_path())?;

    let mut merkle_entries: Vec<ParsedShaderEntry> = Vec::with_capacity(manifest.entries.len());
    let mut active_identities: Vec<String> = Vec::with_capacity(manifest.entries.len() * 16);

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
        let entry_node =
            include_merkle::traverse_build(&mut entry_graph, &base_path, &canonical_path, 0);
        include_merkle::traverse_patch(&mut entry_graph, entry_node);
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

    // Query what identities are missing from the remote endpoint.
    let missing_identities = transport::query_missing_identities(&config, &active_identities)?;

    // Upload missing identities to the remote endpoint.
    for missing_identity in &missing_identities {
        info!("Uploading missing identity: {}", missing_identity);
        let identity_data = fetch_from_cache(cache_path, &missing_identity)?;
        let uploaded_identity =
            transport::upload_identity(&config, &missing_identity, &identity_data)?;
        assert_eq!(missing_identity, &uploaded_identity);
    }

    let mut records: Vec<ShaderRecord> = Vec::new();

    // Compile HLSL -> DXIL
    for ParsedShaderEntry {
        ref name,
        ref profile,
        ref entry_point,
        ref identity,
        ref output,
        ref language,
        ref defines,
    } in &merkle_entries
    {
        if language != "hlsl" {
            // Not an HLSL source file
            continue;
        }

        if output.iter().find(|name| name == &"dxil").is_none() {
            // DXIL output is not requested for this entry point
            continue;
        }

        info!(
            "Compiling '{}' [{}]: entry:[{}], file:[{:?}], DXIL, defines:{:#?}",
            profile,
            name,
            entry_point,
            &cache_path.join(&identity),
            defines,
        );

        let mut define_map: HashMap<String, String> = HashMap::new();
        defines.iter().for_each(|(name, value)| {
            define_map.insert(name.to_string(), value.to_string());
        });

        let (target_profile, target_version) = parse_dxc_profile_version(profile.as_ref());
        let options = drivers::dxc::CompileOptions {
            entry_point: entry_point.clone(),
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
            name: name.to_owned(),
            entry: entry_point.clone(),
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

        let results = transport::compile_dxc(&config, &identity, options)?;
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
                trace!("   ---\nOutput:\n---\n{}", result.output);
            }
            if !result.errors.is_empty() {
                error!("   ---\nErrors:\n---\n{}", result.errors);
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

        records.push(record);
    }

    // Compile HLSL -> SPIR-V
    for ParsedShaderEntry {
        ref name,
        ref profile,
        ref entry_point,
        ref identity,
        ref output,
        ref language,
        ref defines,
    } in &merkle_entries
    {
        if language != "hlsl" {
            // Not an HLSL source file
            continue;
        }

        if output.iter().find(|name| name == &"spirv").is_none() {
            // SPIR-V output is not requested for this entry point
            continue;
        }

        info!(
            "Compiling '{}' [{}]: entry:[{}], file:[{:?}], SPIR-V, defines:{:#?}",
            profile,
            name,
            entry_point,
            &cache_path.join(&identity),
            defines,
        );

        let mut define_map: HashMap<String, String> = HashMap::new();
        defines.iter().for_each(|(name, value)| {
            define_map.insert(name.to_string(), value.to_string());
        });

        let (target_profile, target_version) = parse_dxc_profile_version(profile.as_ref());
        let options = drivers::dxc::CompileOptions {
            entry_point: entry_point.clone(),
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
                binding_registers: Vec::new(),
                opt_config: Vec::new(),
                debug_info: Vec::new(),
                extensions: Vec::new(),
            }),
        };

        let mut record = ShaderRecord {
            name: name.to_owned(),
            entry: entry_point.clone(),
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

        let results = transport::compile_dxc(&config, &identity, options)?;
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
                trace!("   ---\nOutput:\n---\n{}", result.output);
            }
            if !result.errors.is_empty() {
                error!("   ---\nErrors:\n---\n{}", result.errors);
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

        records.push(record);
    }

    // Compile GLSL -> SPIR-V
    for ParsedShaderEntry {
        ref name,
        ref profile,
        ref entry_point,
        ref identity,
        ref output,
        ref language,
        ref defines,
    } in &merkle_entries
    {
        if language != "glsl" {
            // Not a GLSL source file
            continue;
        }

        if output.iter().find(|name| name == &"spirv").is_none() {
            // SPIR-V output is not requested for this entry point
            continue;
        }

        info!(
            "Compiling '{}' [{}]: entry:[{}], file:[{:?}], SPIR-V, defines:{:?}",
            profile,
            name,
            entry_point,
            &cache_path.join(&identity),
            defines,
        );

        let mut define_map: HashMap<String, String> = HashMap::new();
        defines.iter().for_each(|(name, value)| {
            define_map.insert(name.to_string(), value.to_string());
        });

        let (target_profile, vulkan_version) = parse_glslc_profile_version(profile.as_ref());
        let options = drivers::shaderc::CompileOptions {
            entry_point: entry_point.clone(),
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
            name: name.to_owned(),
            entry: entry_point.clone(),
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

        let results = transport::compile_glslc(&config, &identity, options)?;
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
                trace!("   ---\nOutput:\n---\n{}", result.output);
            }
            if !result.errors.is_empty() {
                error!("   ---\nErrors:\n---\n{}", result.errors);
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

        records.push(record);
    }

    if process_opt.validate {
        for record in &mut records {
            for mut artifact in &mut record.artifacts {
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
                            artifact.identity = if let Some(ref identity) = &signed_result.identity
                            {
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
            }
        }
    }

    if process_opt.download || (process_opt.output.is_some() && process_opt.embed) {
        for record in &records {
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

    if let Some(ref output_path) = process_opt.output {
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
        let manifest_file = File::create(output_path)?;
        let mut manifest_writer = BufWriter::new(manifest_file);
        manifest_writer.write_all(&manifest_data)?;
    }

    Ok(())
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

fn _compress_test() -> Result<()> {
    let root_dir = Path::new("./tests");
    let shader_file = root_dir.join("data/CodeGenHLSL/Samples/MiniEngine/ParticleSpawnCS.hlsl");
    let shader_text = utilities::read_file_string(&shader_file)?;
    let shader_data = shader_text.as_bytes();

    let identity = encode_data(&shader_data, &Encoding::Identity)?;
    let deflate = encode_data(&shader_data, &Encoding::Deflate)?;
    let gzip = encode_data(&shader_data, &Encoding::Gzip)?;
    let brotli = encode_data(&shader_data, &Encoding::Brotli)?;
    let zlib = encode_data(&shader_data, &Encoding::Zlib)?;
    let zstd = encode_data(&shader_data, &Encoding::Zstd)?;
    let lz4 = encode_data(&shader_data, &Encoding::Lz4)?;
    let lzma = encode_data(&shader_data, &Encoding::Lzma)?;
    let lzma2 = encode_data(&shader_data, &Encoding::Lzma2)?;
    let bincode = encode_data(&shader_data, &Encoding::BinCode)?;
    //let smolv = encode_data(&shader_data, &Encoding::SmolV)?;

    assert_eq!(shader_data, identity.as_slice());
    assert_ne!(shader_data, deflate.as_slice());
    assert_ne!(shader_data, gzip.as_slice());
    assert_ne!(shader_data, brotli.as_slice());
    assert_ne!(shader_data, zlib.as_slice());
    assert_ne!(shader_data, zstd.as_slice());
    assert_ne!(shader_data, lz4.as_slice());
    assert_ne!(shader_data, lzma.as_slice());
    assert_ne!(shader_data, lzma2.as_slice());
    assert_ne!(shader_data, bincode.as_slice());
    //assert_ne!(shader_data, smolv.as_slice());

    let identity_prime = decode_data(&identity, &Encoding::Identity)?;
    let deflate_prime = decode_data(&deflate, &Encoding::Deflate)?;
    let gzip_prime = decode_data(&gzip, &Encoding::Gzip)?;
    let brotli_prime = decode_data(&brotli, &Encoding::Brotli)?;
    let zlib_prime = decode_data(&zlib, &Encoding::Zlib)?;
    let zstd_prime = decode_data(&zstd, &Encoding::Zstd)?;
    let lz4_prime = decode_data(&lz4, &Encoding::Lz4)?;
    let lzma_prime = decode_data(&lzma, &Encoding::Lzma)?;
    let lzma2_prime = decode_data(&lzma2, &Encoding::Lzma2)?;
    let bincode_prime = decode_data(&bincode, &Encoding::BinCode)?;
    //let smolv_prime = decode_data(&smolv, &Encoding::SmolV)?;

    let identity_len = identity.len() as f32;
    let deflate_len = deflate.len() as f32;
    let gzip_len = gzip.len() as f32;
    let brotli_len = brotli.len() as f32;
    let zlib_len = zlib.len() as f32;
    let zstd_len = zstd.len() as f32;
    let lz4_len = lz4.len() as f32;
    let lzma_len = lzma.len() as f32;
    let lzma2_len = lzma2.len() as f32;
    let bincode_len = bincode.len() as f32;
    //let smolv_len = smolv.len() as f32;

    println!(
        "Deflate is {}% smaller than Identity",
        (identity_len - deflate_len) / identity_len * 100f32
    );
    println!(
        "Gzip is {}% smaller than Identity",
        (identity_len - gzip_len) / identity_len * 100f32
    );
    println!(
        "Brotli is {}% smaller than Identity",
        (identity_len - brotli_len) / identity_len * 100f32
    );
    println!(
        "Zlib is {}% smaller than Identity",
        (identity_len - zlib_len) / identity_len * 100f32
    );
    println!(
        "Zstd is {}% smaller than Identity",
        (identity_len - zstd_len) / identity_len * 100f32
    );
    println!(
        "Lz4 is {}% smaller than Identity",
        (identity_len - lz4_len) / identity_len * 100f32
    );
    println!(
        "Lzma is {}% smaller than Identity",
        (identity_len - lzma_len) / identity_len * 100f32
    );
    println!(
        "Lzma2 is {}% smaller than Identity",
        (identity_len - lzma2_len) / identity_len * 100f32
    );
    println!(
        "BinCode is {}% smaller than Identity",
        (identity_len - bincode_len) / identity_len * 100f32
    );
    //println!("Smol-V is {}% smaller than Identity", (identity_len - smolv_len) / identity_len * 100f32);

    assert_eq!(shader_data, identity_prime.as_slice());
    assert_eq!(shader_data, deflate_prime.as_slice());
    assert_eq!(shader_data, gzip_prime.as_slice());
    assert_eq!(shader_data, brotli_prime.as_slice());
    assert_eq!(shader_data, zlib_prime.as_slice());
    assert_eq!(shader_data, zstd_prime.as_slice());
    assert_eq!(shader_data, lz4_prime.as_slice());
    assert_eq!(shader_data, lzma_prime.as_slice());
    assert_eq!(shader_data, lzma2_prime.as_slice());
    assert_eq!(shader_data, bincode_prime.as_slice());
    //assert_eq!(shader_data, smolv_prime.as_slice());

    Ok(())
}
