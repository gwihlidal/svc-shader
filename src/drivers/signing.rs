use crate::error::{Error, ErrorKind, Result};
use failure::ResultExt;
use filebuffer::FileBuffer;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::process::Command;

use crate::utilities::{compute_file_identity, wine_wrap, TempFile};

lazy_static! {
    pub static ref SIGN_PATH: String = env::var("SIGN_PATH")
        .expect("SIGN_PATH must be set")
        .to_string();
}

lazy_static! {
    pub static ref SIGN_IDENTITY: String = {
        // The dxil.dll is all that matters, not the shim wrapper
        let path = Path::new(&*SIGN_PATH).parent().unwrap().join("dxil.dll");
        compute_file_identity(path).expect("failed to calculate SIGN identity")
    };
}

lazy_static! {
    pub static ref SIGN_ENABLED: bool = { env::var("SIGN_PATH").is_ok() };
}

pub fn sign_dxil(input: &[u8], temp_path: &Path) -> Result<(Vec<u8>, String)> {
    let input_handle = TempFile::new(&temp_path);
    let input_path = &input_handle.path();
    {
        let input_file = File::create(input_path).with_context(|_| ErrorKind::path(input_path))?;
        let mut input_writer = BufWriter::new(input_file);
        input_writer
            .write_all(input)
            .with_context(|_| ErrorKind::path(input_path))?;
    }

    let output_handle = TempFile::new(&temp_path);
    let output_path = &output_handle.path();

    let (command, mut args) = wine_wrap(SIGN_PATH.to_string());

    args.push("--input".to_string());
    args.push(input_handle.as_str());

    args.push("--output".to_string());
    args.push(output_handle.as_str());

    let mut output = Command::new(command);
    for arg in &args {
        output.arg(arg);
    }

    let output = output.output();
    match output {
        Ok(ref output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if output.status.success() {
                let output_buffer = FileBuffer::open(&output_path)
                    .with_context(|_| ErrorKind::path(&output_path))?;
                let result = output_buffer.to_vec();
                Ok((result, stdout.to_string()))
            } else {
                Err(Error::process(format!(
                    "failed to run command - details: {:?} - {:?}",
                    stdout.to_string(),
                    stderr.to_string()
                )))
            }
        }
        Err(err) => Err(Error::bug(format!(
            "failed to run command: {:?} - details: {:?}",
            args, err
        ))),
    }
}

pub fn identity_from_request(unsigned_identity: &str) -> String {
    use base58::ToBase58;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::default();
    hasher.input(&*SIGN_IDENTITY.as_bytes());
    hasher.input(&unsigned_identity.as_bytes());
    hasher.result().to_vec().to_base58()
}
