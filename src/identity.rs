use sha2::{Digest, Sha256};

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub raw: Vec<u8>,
    pub txt: String,
}

pub fn compute_data_identity(data: &[u8]) -> Identity {
    // create a Sha256 object
    let mut hasher = Sha256::default();

    // write input data
    hasher.input(data);

    // read hash digest and consume hasher
    let output_raw = hasher.result().to_vec();
    let output_b58 = smush::encode(
        &output_raw,
        smush::Encoding::Base58,
        smush::Quality::Default,
    )
    .unwrap();
    let output_txt = String::from_utf8(output_b58).unwrap();

    Identity {
        raw: output_raw,
        txt: output_txt,
    }
}
