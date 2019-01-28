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

pub fn disassemble_spirv(
    transform_path: &Path,
    storage_path: &Path,
    temp_path: &Path,
    request: &proto::drivers::spirv_dis::DisassembleRequest,
) -> Result<Vec<proto::service::ProcessOutput>> {
    let source_identity = match request.identity {
        Some(ref identity) => identity.sha256_base58.to_owned(),
        None => {
            return Err(Error::process("SPIR-V source identity is not specified"));
        }
    };

    let options = match request.options {
        Some(ref options) => options,
        None => {
            return Err(Error::process("Disassemble options are not specified"));
        }
    };

    let source_path = storage_path.join(&source_identity);
    if !path_exists(&source_path) {
        return Err(Error::process(&format!(
            "SPIR-V source identity '{}' is invalid (not present in storage)",
            source_identity
        )));
    }

    let request_identity = drivers::spirv_dis::identity_from_request(&source_identity, &options);
    match super::caching::fetch_from_cache(transform_path, &request_identity) {
        Some(ref output) => Ok(output.to_vec()),
        None => {
            let dis_output =
                drivers::spirv_dis::disassemble(&Path::new(&source_identity), &options, &temp_path);
            let dis_output = match dis_output {
                Ok(ref dis_output) => dis_output,
                Err(err) => {
                    return Err(Error::process(&format!(
                        "SPIR-V disassembly of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
            };

            let mut dis_results: Vec<(String /* name */, String /* identity */)> = Vec::new();

            if dis_output.0.len() > 0 {
                let dis_identity = compute_data_identity(&dis_output.0);
                let dis_path = storage_path.join(&dis_identity.txt);
                let dis_file = File::create(&dis_path);
                if let Err(err) = dis_file {
                    return Err(Error::process(&format!(
                        "SPIR-V disassembly of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
                let mut dis_writer = BufWriter::new(dis_file.unwrap());
                if let Err(err) = dis_writer.write_all(&dis_output.0) {
                    return Err(Error::process(&format!(
                        "SPIR-V disassembly of '{}' failed! err={:?}",
                        source_identity, err
                    )));
                }
                dis_results.push(("Disassembly".to_string(), dis_identity.txt));
            }

            let transforms: Vec<ProcessTransform> = dis_results
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

            let output: Vec<proto::service::ProcessOutput> = dis_results
                .iter()
                .map(|(name, identity)| proto::service::ProcessOutput {
                    name: name.to_string(),
                    output: dis_output.1.to_string(),
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
