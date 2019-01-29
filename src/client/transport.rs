extern crate tower_http;
extern crate tower_util;

use crate::error::{Error, Result};
use crate::identity::compute_data_identity;
use crate::proto::common::StorageContent;
use crate::proto::common::StorageIdentity;
use crate::proto::drivers;
use crate::proto::service;
use crate::proto::service::DownloadRequest;
use crate::proto::service::ProcessOutput;
use futures::future::Future;
use futures::stream::Stream;
use std::io::Write;
use tokio::executor::DefaultExecutor;
use tower_grpc::codegen::client::http::Uri;
use tower_grpc::Error as GrpcError;
use tower_grpc::Request;
use tower_h2::client;
use tower_http::add_origin;
use tower_util::MakeService;

pub struct Config {
    pub address: String,
    pub window_size: Option<u32>,
    pub connection_window_size: Option<u32>,
}

struct EndPoint {
    address: std::net::SocketAddr,
}

impl EndPoint {
    pub fn new(address: &str) -> Self {
        EndPoint {
            address: address
                .parse::<std::net::SocketAddr>()
                .expect("invalid address"),
        }
    }
}

impl tokio_connect::Connect for EndPoint {
    type Connected = tokio::net::tcp::TcpStream;
    type Error = ::std::io::Error;
    type Future = tokio::net::tcp::ConnectFuture;

    fn connect(&self) -> Self::Future {
        tokio::net::tcp::TcpStream::connect(&self.address)
    }
}

pub fn query_missing_identities(config: &Config, identities: &[String]) -> Result<Vec<String>> {
    let query_requests: Vec<StorageIdentity> = identities
        .iter()
        .map(|identity| StorageIdentity {
            sha256_base58: identity.to_string(),
        })
        .collect();
    let query_request_stream = futures::stream::iter_ok(query_requests);

    let mut h2_settings = h2::client::Builder::default();
    if let Some(window_size) = config.window_size {
        h2_settings.initial_window_size(window_size); // for an RPC
    }
    if let Some(connection_window_size) = config.connection_window_size {
        h2_settings.initial_connection_window_size(connection_window_size); // for a connection
    }

    let uri: Uri = format!("http://{}", &config.address).parse().unwrap();

    let mut make_client = client::Connect::new(
        EndPoint::new(&config.address),
        h2_settings,
        DefaultExecutor::current(),
    );
    let rg = make_client
        .make_service(())
        .map(move |conn| {
            let conn = add_origin::Builder::new().uri(uri).build(conn).unwrap();
            service::client::Shader::new(conn)
        })
        .and_then(|mut client| {
            client
                .query(Request::new(query_request_stream))
                .map_err(|err| panic!("gRPC request failed; err={:?}", err))
        })
        .map_err(|err| {
            let status = tower_grpc::Status::with_code_and_message(
                tower_grpc::Code::Aborted,
                err.to_string(),
            );
            GrpcError::Grpc(status)
        })
        .and_then(|response_stream| {
            // Convert the stream into a plain Vec
            response_stream.into_inner().collect()
        });

    let mut rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(rg) {
        Ok(results) => {
            let mut missing_identities: Vec<String> = Vec::with_capacity(results.len());
            for result in &results {
                if let Some(ref identity) = &result.identity {
                    if result.exists {
                        // Identity already exists!
                    } else {
                        missing_identities.push(identity.sha256_base58.to_owned());
                    }
                }
            }
            Ok(missing_identities)
        }
        Err(err) => Err(Error::grpc(err)),
    }
}

pub fn upload_identity(config: &Config, identity: &str, data: &[u8]) -> Result<String> {
    let meta_request = StorageContent {
        identity: Some(StorageIdentity {
            sha256_base58: identity.to_string(),
        }),
        encoding: "identity".to_string(),
        type_: "application/octet-stream".to_string(),
        total_length: data.len() as u64,
        ..Default::default()
    };

    // Is this efficient? (aside from the obvious "whole file is first loaded into memory")
    // Need to ensure we stream the input in with zero allocations (or minimal)
    // Iterator would likely be better:
    // - https://medium.com/@KevinHoffman/creating-a-stream-chunking-iterator-in-rust-d4063ffd21ed
    // Also relevant (Content-Defined Chunking):
    // - https://remram44.github.io/cdchunking-rs/cdchunking/index.html
    // - https://github.com/remram44/cdchunking-rs
    // - https://restic.net/blog/2015-09-12/restic-foundation1-cdc
    let upload_requests: Vec<StorageContent> = data
        .chunks(1024 * 1024)
        //.chunks(32 * 1024)
        .map(|chunk_data| {
            let mut request = meta_request.clone();
            request.chunk_data = chunk_data.to_vec();
            request
        })
        .collect();

    let upload_request_stream = futures::stream::iter_ok(upload_requests);

    let mut h2_settings = h2::client::Builder::default();
    if let Some(window_size) = config.window_size {
        h2_settings.initial_window_size(window_size); // for an RPC
    }
    if let Some(connection_window_size) = config.connection_window_size {
        h2_settings.initial_connection_window_size(connection_window_size); // for a connection
    }

    let uri: Uri = format!("http://{}", &config.address).parse().unwrap();

    let mut make_client = client::Connect::new(
        EndPoint::new(&config.address),
        h2_settings,
        DefaultExecutor::current(),
    );
    let rg = make_client
        .make_service(())
        .map(move |conn| {
            let conn = add_origin::Builder::new().uri(uri).build(conn).unwrap();
            service::client::Shader::new(conn)
        })
        .and_then(|mut client| {
            client
                .upload(Request::new(upload_request_stream))
                .map_err(|e| panic!("gRPC request failed; err={:?}", e))
        })
        .map_err(|e| panic!("gRPC request failed; err={:?}", e));

    let mut rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(rg) {
        Ok(result) => {
            let result = result.into_inner();
            //println!("Result is {:?}", result);
            Ok(result.sha256_base58)
        }
        Err(err) => {
            panic!("ERROR; err={:?}", err);
        }
    }
}

pub fn download_identity(config: &Config, identity: &str) -> Result<Vec<u8>> {
    trace!("Downloading: {}", identity);

    let request = DownloadRequest {
        identity: Some(StorageIdentity {
            sha256_base58: identity.to_string(),
        }),
        encoding: "identity".to_string(),
    };

    let mut h2_settings = h2::client::Builder::default();
    if let Some(window_size) = config.window_size {
        h2_settings.initial_window_size(window_size); // for an RPC
    }
    if let Some(connection_window_size) = config.connection_window_size {
        h2_settings.initial_connection_window_size(connection_window_size); // for a connection
    }

    let uri: Uri = format!("http://{}", &config.address).parse().unwrap();

    let mut make_client = client::Connect::new(
        EndPoint::new(&config.address),
        h2_settings,
        DefaultExecutor::current(),
    );
    let rg = make_client
        .make_service(())
        .map(move |conn| {
            let conn = add_origin::Builder::new().uri(uri).build(conn).unwrap();
            service::client::Shader::new(conn)
        })
        .and_then(|mut client| {
            client
                .download(Request::new(request))
                .map_err(|err| panic!("gRPC request failed; err={:?}", err))
        })
        .map_err(|err| {
            let status = tower_grpc::Status::with_code_and_message(
                tower_grpc::Code::Aborted,
                err.to_string(),
            );
            GrpcError::Grpc(status)
        })
        .and_then(|response_stream| {
            // Convert the stream into a plain Vec
            response_stream.into_inner().collect()
        });

    struct DownloadContext {
        writer: Option<std::io::Cursor<Vec<u8>>>,
        content_encoding: String,
        content_type: String,
        total_length: usize,
    }

    let mut download_context = DownloadContext {
        writer: None,
        content_encoding: String::new(),
        content_type: String::new(),
        total_length: 0,
    };

    let mut rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(rg) {
        Ok(results) => {
            for content_part in &results {
                if download_context.writer.is_none() {
                    download_context.writer = Some(std::io::Cursor::new(Vec::with_capacity(
                        content_part.total_length as usize,
                    )));
                    assert!(download_context.writer.is_some());
                    download_context.content_encoding = content_part.encoding.clone();
                    download_context.content_type = content_part.type_.clone();
                    download_context.total_length = content_part.total_length as usize;
                }

                if let Some(writer) = &mut download_context.writer {
                    if let Err(err) = writer.write(&content_part.chunk_data) {
                        error!("Error occurred writing chunk bytes! {}", err);
                    }
                }
            }

            if let Some(ref writer) = download_context.writer {
                let bytes_received = writer.position();
                let data_buffer: &Vec<u8> = writer.get_ref();
                let data_identity = compute_data_identity(&data_buffer);
                assert_eq!(bytes_received as usize, data_buffer.len());
                assert_eq!(data_identity.txt, identity);
                Ok(data_buffer.clone())
            } else {
                Ok(Vec::new())
            }
        }
        Err(err) => Err(Error::grpc(err)),
    }
}

pub fn sign_dxil(config: &Config, identity: &str) -> Result<Vec<ProcessOutput>> {
    let request = drivers::sign::SignRequest {
        identity: Some(StorageIdentity {
            sha256_base58: identity.to_string(),
        }),
    };

    let mut h2_settings = h2::client::Builder::default();
    if let Some(window_size) = config.window_size {
        h2_settings.initial_window_size(window_size); // for an RPC
    }
    if let Some(connection_window_size) = config.connection_window_size {
        h2_settings.initial_connection_window_size(connection_window_size); // for a connection
    }

    let uri: Uri = format!("http://{}", &config.address).parse().unwrap();

    let mut make_client = client::Connect::new(
        EndPoint::new(&config.address),
        h2_settings,
        DefaultExecutor::current(),
    );
    let rg = make_client
        .make_service(())
        .map(move |conn| {
            let conn = add_origin::Builder::new().uri(uri).build(conn).unwrap();
            service::client::Shader::new(conn)
        })
        .and_then(|mut client| {
            client
                .sign_dxil(Request::new(request))
                .map_err(|err| panic!("gRPC request failed; err={:?}", err))
        })
        .map_err(|err| {
            let status = tower_grpc::Status::with_code_and_message(
                tower_grpc::Code::Aborted,
                err.to_string(),
            );
            GrpcError::Grpc(status)
        })
        .and_then(|response_stream| {
            // Convert the stream into a plain Vec
            response_stream.into_inner().collect()
        });

    let mut rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(rg) {
        Ok(results) => Ok(results),
        Err(err) => Err(Error::process(format!("error signing dxil: err={:?}", err))),
    }
}

pub fn compile_dxc(
    config: &Config,
    identity: &str,
    options: drivers::dxc::CompileOptions,
) -> Result<Vec<ProcessOutput>> {
    let identity = Some(StorageIdentity {
        sha256_base58: identity.to_string(),
    });

    let request = drivers::dxc::CompileRequest {
        identity,
        options: Some(options),
    };

    let mut h2_settings = h2::client::Builder::default();
    if let Some(window_size) = config.window_size {
        h2_settings.initial_window_size(window_size); // for an RPC
    }
    if let Some(connection_window_size) = config.connection_window_size {
        h2_settings.initial_connection_window_size(connection_window_size); // for a connection
    }

    let uri: Uri = format!("http://{}", &config.address).parse().unwrap();

    let mut make_client = client::Connect::new(
        EndPoint::new(&config.address),
        h2_settings,
        DefaultExecutor::current(),
    );
    let rg = make_client
        .make_service(())
        .map(move |conn| {
            let conn = add_origin::Builder::new().uri(uri).build(conn).unwrap();
            service::client::Shader::new(conn)
        })
        .and_then(|mut client| {
            client
                .compile_dxc(Request::new(request))
                .map_err(|err| panic!("gRPC request failed; err={:?}", err))
        })
        .map_err(|err| {
            let status = tower_grpc::Status::with_code_and_message(
                tower_grpc::Code::Aborted,
                err.to_string(),
            );
            GrpcError::Grpc(status)
        })
        .and_then(|response_stream| {
            // Convert the stream into a plain Vec
            response_stream.into_inner().collect()
        });

    let mut rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(rg) {
        Ok(results) => Ok(results),
        Err(err) => Err(Error::process(format!(
            "error compiling dxc: err={:?}",
            err
        ))),
    }
}

pub fn compile_glslc(
    config: &Config,
    identity: &str,
    options: drivers::shaderc::CompileOptions,
) -> Result<Vec<ProcessOutput>> {
    let identity = Some(StorageIdentity {
        sha256_base58: identity.to_string(),
    });

    let request = drivers::shaderc::CompileRequest {
        identity,
        options: Some(options),
    };

    let mut h2_settings = h2::client::Builder::default();
    if let Some(window_size) = config.window_size {
        h2_settings.initial_window_size(window_size); // for an RPC
    }
    if let Some(connection_window_size) = config.connection_window_size {
        h2_settings.initial_connection_window_size(connection_window_size); // for a connection
    }

    let uri: Uri = format!("http://{}", &config.address).parse().unwrap();

    let mut make_client = client::Connect::new(
        EndPoint::new(&config.address),
        h2_settings,
        DefaultExecutor::current(),
    );
    let rg = make_client
        .make_service(())
        .map(move |conn| {
            let conn = add_origin::Builder::new().uri(uri).build(conn).unwrap();
            service::client::Shader::new(conn)
        })
        .and_then(|mut client| {
            client
                .compile_glslc(Request::new(request))
                .map_err(|err| panic!("gRPC request failed; err={:?}", err))
        })
        .map_err(|err| {
            let status = tower_grpc::Status::with_code_and_message(
                tower_grpc::Code::Aborted,
                err.to_string(),
            );
            GrpcError::Grpc(status)
        })
        .and_then(|response_stream| {
            // Convert the stream into a plain Vec
            response_stream.into_inner().collect()
        });

    let mut rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(rg) {
        Ok(results) => Ok(results),
        Err(err) => Err(Error::process(format!(
            "error compiling glslc: err={:?}",
            err
        ))),
    }
}
