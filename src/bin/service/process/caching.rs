use bincode::{deserialize, serialize};
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;
use svc_shader::error::{Error, ErrorKind, Result};
use svc_shader::proto;
use svc_shader::utilities::{path_exists, read_file};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ProcessTransform {
    pub name: String,
    pub identity: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ProcessTransformList(pub Vec<ProcessTransform>);

impl ProcessTransformList {
    pub fn encode(&self, transform_dir: &Path, request_identity: &str) -> Result<()> {
        let transform_path = transform_dir.join(request_identity);
        let transform_file = File::create(transform_path)?;
        let encoded: Vec<u8> = serialize(&self).unwrap();
        let mut transform_writer = BufWriter::new(transform_file);
        transform_writer.write_all(&encoded)?;
        Ok(())
    }

    pub fn decode(transform_dir: &Path, request_identity: &str) -> Result<ProcessTransformList> {
        let transform_path = transform_dir.join(request_identity);
        let transform_data = read_file(&transform_path)?;
        let decoded: ProcessTransformList = deserialize(&transform_data[..]).unwrap();
        Ok(decoded)
        /*if let Ok(decoded) = decoded {
            Ok(decoded)
        } else {
            Err(Error::parse(format!("failed to parse transform list: {:?}", transform_path)))
        }*/
    }
}

pub fn fetch_from_cache(
    transform_path: &Path,
    request_identity: &str,
) -> Option<Vec<proto::service::ProcessOutput>> {
    if path_exists(&transform_path.join(&request_identity)) {
        let transform_list =
            ProcessTransformList::decode(&transform_path, &request_identity).unwrap();
        Some(
            transform_list
                .0
                .iter()
                .map(|output| proto::service::ProcessOutput {
                    name: output.name.to_owned(),
                    output: String::new(),
                    errors: String::new(),
                    identity: Some(proto::common::StorageIdentity {
                        sha256_base58: output.identity.to_owned(),
                    }),
                })
                .collect::<Vec<proto::service::ProcessOutput>>(),
        )
    } else {
        None
    }
}
