use crate::process::caching::*;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;
use svc_shader::drivers;
use svc_shader::error::{Error, ErrorKind, Result};
use svc_shader::identity::compute_data_identity;
use svc_shader::proto;
use svc_shader::utilities::read_file;
use svc_shader::utilities::{compute_identity, path_exists, TempDir};

pub fn compile_shaderc(
    transform_path: &Path,
    storage_path: &Path,
    temp_path: &Path,
    request: &proto::drivers::shaderc::CompileRequest,
) -> Result<Vec<proto::service::ProcessOutput>> {
    let source_identity = match request.identity {
        Some(ref identity) => identity.sha256_base58.to_owned(),
        None => {
            return Err(Error::process("Shader source identity is not specified"));
        }
    };

    let options = match request.options {
        Some(ref options) => options,
        None => {
            return Err(Error::process("Compile options are not specified"));
        }
    };

    let source_path = storage_path.join(&source_identity);
    if !path_exists(&source_path) {
        return Err(Error::process(&format!(
            "Shader source identity '{}' is invalid (not present in storage)",
            source_identity
        )));
    }

    let request_identity = drivers::shaderc::identity_from_request(&source_identity, &options);
    match super::caching::fetch_from_cache(transform_path, &request_identity) {
        Some(ref output) => Ok(output.to_vec()),
        None => {
            let source_data = read_file(source_path).unwrap();
            assert_eq!(compute_identity(&source_data), source_identity);

            let working_handle = TempDir::new(&temp_path);
            let working_path = &working_handle.path();
            working_handle.create().unwrap();

            let input_path = working_path.join("input.glsl");
            {
                let input_file = File::create(&input_path);
                if let Err(err) = input_file {
                    return Err(Error::process(&format!(
                        "GLSLC compilation of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
                let mut input_writer = BufWriter::new(input_file.unwrap());
                if let Err(err) = input_writer.write_all(&source_data) {
                    return Err(Error::process(&format!(
                        "GLSLC compilation of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
            }

            let output_path = working_path.join("output.spirv");

            let mut glslc = drivers::shaderc::Compiler::new(options);
            glslc.include_path(&storage_path);

            let glslc_output = glslc.compile(&working_path, &input_path, &output_path);
            let glslc_output = match glslc_output {
                Ok(ref glslc_output) => glslc_output,
                Err(err) => {
                    return Err(Error::process(&format!(
                        "GLSLC compilation of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
            };

            let mut glslc_results: Vec<(String /* name */, String /* identity */)> = Vec::new();

            if !glslc_output.0.code.is_empty() {
                let code_identity = compute_data_identity(&glslc_output.0.code);
                let code_path = storage_path.join(&code_identity.txt);
                let code_file = File::create(&code_path);
                if let Err(err) = code_file {
                    return Err(Error::process(&format!(
                        "GLSLC [code] compilation of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
                let mut code_writer = BufWriter::new(code_file.unwrap());
                if let Err(err) = code_writer.write_all(&glslc_output.0.code) {
                    return Err(Error::process(&format!(
                        "GLSLC [code] compilation of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
                glslc_results.push(("Code".to_string(), code_identity.txt));
            }

            let transforms: Vec<ProcessTransform> = glslc_results
                .iter()
                .map(|(name, identity)| ProcessTransform {
                    name: name.to_string(),
                    identity: identity.to_string(),
                })
                .collect();

            let transform_list = ProcessTransformList(transforms);

            transform_list
                .encode(&transform_path, &request_identity)
                .unwrap();

            let output: Vec<proto::service::ProcessOutput> = glslc_results
                .iter()
                .map(|(name, identity)| proto::service::ProcessOutput {
                    name: name.to_string(),
                    output: glslc_output.1.to_string(),
                    errors: String::new(),
                    identity: Some(proto::common::StorageIdentity {
                        sha256_base58: identity.to_string(),
                    }),
                })
                .collect();

            Ok(output)
        }
    }
}

pub fn compile_dxc(
    transform_path: &Path,
    storage_path: &Path,
    temp_path: &Path,
    request: &proto::drivers::dxc::CompileRequest,
) -> Result<Vec<proto::service::ProcessOutput>> {
    let source_identity = match request.identity {
        Some(ref identity) => identity.sha256_base58.to_owned(),
        None => {
            return Err(Error::process("Shader source identity is not specified"));
        }
    };

    let options = match request.options {
        Some(ref options) => options,
        None => {
            return Err(Error::process("Compile options are not specified"));
        }
    };

    let input_path = storage_path.join(&source_identity);
    if !path_exists(&input_path) {
        return Err(Error::process(&format!(
            "Shader source identity '{}' is invalid (not present in storage)",
            source_identity
        )));
    }

    let request_identity = drivers::dxc::identity_from_request(&source_identity, &options);
    match super::caching::fetch_from_cache(transform_path, &request_identity) {
        Some(ref output) => Ok(output.to_vec()),
        None => {
            let temp_handle = TempDir::new(&temp_path);
            let temp_path = &temp_handle.path();
            temp_handle.create().unwrap();

            let dxil_path = temp_path.join("output.dxil");
            let debug_path = temp_path.join("output.debug");
            let listing_path = temp_path.join("output.list");

            let mut dxc = drivers::dxc::Compiler::new(options);
            dxc.include_path(&storage_path);

            let dxc_output = dxc.compile(
                &storage_path,
                &input_path,
                &dxil_path,
                &listing_path,
                &debug_path,
            );

            let dxc_output = match dxc_output {
                Ok(ref dxc_output) => dxc_output,
                Err(err) => {
                    return Err(Error::process(&format!(
                        "DXC compilation of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
            };

            let mut dxc_results: Vec<(String /* name */, String /* identity */)> = Vec::new();

            if !dxc_output.0.code.is_empty() {
                let code_identity = compute_data_identity(&dxc_output.0.code);
                let code_path = storage_path.join(&code_identity.txt);
                let code_file = File::create(&code_path);
                if let Err(err) = code_file {
                    return Err(Error::process(&format!(
                        "DXC [code] compilation of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
                let mut code_writer = BufWriter::new(code_file.unwrap());
                if let Err(err) = code_writer.write_all(&dxc_output.0.code) {
                    return Err(Error::process(&format!(
                        "DXC [code] compilation of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
                dxc_results.push(("Code".to_string(), code_identity.txt));
            }

            if !dxc_output.0.listing.is_empty() {
                let listing_identity = compute_data_identity(&dxc_output.0.listing);
                let listing_path = storage_path.join(&listing_identity.txt);
                let listing_file = File::create(&listing_path);
                if let Err(err) = listing_file {
                    return Err(Error::process(&format!(
                        "DXC [listing] compilation of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
                let mut listing_writer = BufWriter::new(listing_file.unwrap());
                if let Err(err) = listing_writer.write_all(&dxc_output.0.listing) {
                    return Err(Error::process(&format!(
                        "DXC [listing] compilation of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
                dxc_results.push(("Listing".to_string(), listing_identity.txt));
            }

            if !dxc_output.0.debug.is_empty() {
                let debug_identity = compute_data_identity(&dxc_output.0.debug);
                let debug_path = storage_path.join(&debug_identity.txt);
                let debug_file = File::create(&debug_path);
                if let Err(err) = debug_file {
                    return Err(Error::process(&format!(
                        "DXC [debug] compilation of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
                let mut debug_writer = BufWriter::new(debug_file.unwrap());
                if let Err(err) = debug_writer.write_all(&dxc_output.0.debug) {
                    return Err(Error::process(&format!(
                        "DXC [debug] compilation of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
                dxc_results.push(("Debug".to_string(), debug_identity.txt));
            }

            let transforms: Vec<ProcessTransform> = dxc_results
                .iter()
                .map(|(name, identity)| ProcessTransform {
                    name: name.to_string(),
                    identity: identity.to_string(),
                })
                .collect();

            let transform_list = ProcessTransformList(transforms);

            transform_list
                .encode(&transform_path, &request_identity)
                .unwrap();

            let output: Vec<proto::service::ProcessOutput> = dxc_results
                .iter()
                .map(|(name, identity)| proto::service::ProcessOutput {
                    name: name.to_string(),
                    output: dxc_output.1.to_string(),
                    errors: String::new(),
                    identity: Some(proto::common::StorageIdentity {
                        sha256_base58: identity.to_string(),
                    }),
                })
                .collect();

            Ok(output)
        }
    }
}

pub fn compile_fxc(
    transform_path: &Path,
    storage_path: &Path,
    temp_path: &Path,
    request: &proto::drivers::fxc::CompileRequest,
) -> Result<Vec<proto::service::ProcessOutput>> {
    let source_identity = match request.identity {
        Some(ref identity) => identity.sha256_base58.to_owned(),
        None => {
            return Err(Error::process("Shader source identity is not specified"));
        }
    };

    let options = match request.options {
        Some(ref options) => options,
        None => {
            return Err(Error::process("Compile options are not specified"));
        }
    };

    let source_path = storage_path.join(&source_identity);
    if !path_exists(&source_path) {
        return Err(Error::process(&format!(
            "Shader source identity '{}' is invalid (not present in storage)",
            source_identity
        )));
    }

    let request_identity = drivers::fxc::identity_from_request(&source_identity, &options);
    match super::caching::fetch_from_cache(transform_path, &request_identity) {
        Some(ref output) => Ok(output.to_vec()),
        None => {
            let source_data = read_file(source_path).unwrap();
            assert_eq!(compute_identity(&source_data), source_identity);

            let working_handle = TempDir::new(&temp_path);
            let working_path = &working_handle.path();
            working_handle.create().unwrap();

            let output: Vec<proto::service::ProcessOutput> = Vec::new();

            Ok(output)
        }
    }
}
