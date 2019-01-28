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

pub fn sign_dxil(
    transform_path: &Path,
    storage_path: &Path,
    temp_path: &Path,
    request: &proto::drivers::sign::SignRequest,
) -> Result<Vec<proto::service::ProcessOutput>> {
    let identity = match request.identity {
        Some(ref identity) => identity.sha256_base58.to_owned(),
        None => {
            return Err(Error::process("DXIL identity is not specified"));
        }
    };

    let request_identity = drivers::signing::identity_from_request(&identity);
    match super::caching::fetch_from_cache(transform_path, &request_identity) {
        Some(ref output) => Ok(output.to_vec()),
        None => {
            let content_path = storage_path.join(&identity);
            let content_data = read_file(&content_path);
            if let Err(err) = content_data {
                return Err(Error::process(&format!(
                    "DXIL identity '{}' is invalid (not present in storage)",
                    identity
                )));
            }
            let content_data = content_data.unwrap();

            let dxil_output = drivers::signing::sign_dxil(&content_data, &temp_path);
            if let Err(err) = dxil_output {
                return Err(Error::process(&format!(
                    "Signing DXIL identity '{}' failed! err={:?}",
                    identity, err
                )));
            }
            let dxil_output = dxil_output.unwrap();

            let signed_identity = compute_data_identity(&dxil_output.0);
            let signed_path = storage_path.join(&signed_identity.txt);
            let signed_file = File::create(signed_path);
            if let Err(err) = signed_file {
                return Err(Error::process(&format!(
                    "Signing DXIL identity '{}' failed! err={:?}",
                    identity, err
                )));
            }

            let mut signed_writer = BufWriter::new(signed_file.unwrap());
            if let Err(err) = signed_writer.write_all(&dxil_output.0) {
                Err(Error::process(&format!(
                    "Signing DXIL identity '{}' failed! err={:?}",
                    identity, err
                )))
            } else {
                let transform_list = ProcessTransformList(vec![ProcessTransform {
                    name: "Signed DXIL".to_string(),
                    identity: signed_identity.txt.clone(),
                }]);
                transform_list
                    .encode(&transform_path, &request_identity)
                    .unwrap();
                Ok(vec![proto::service::ProcessOutput {
                    name: "Signed DXIL".to_string(),
                    output: dxil_output.1,
                    errors: String::new(),
                    identity: Some(proto::common::StorageIdentity {
                        sha256_base58: signed_identity.txt,
                    }),
                }])
            }
        }
    }
}
