extern crate tower_grpc_build;

fn main() {
    build_proto();
}

fn build_proto() {
    let proto_files = &[
        "proto/common.proto",
        "proto/dxc.proto",
        "proto/fxc.proto",
        "proto/rga.proto",
        "proto/service.proto",
        "proto/shaderc.proto",
        "proto/sign.proto",
        "proto/spirv_as.proto",
        "proto/spirv_cross.proto",
    ];
    let proto_dirs = &["proto"];

    tower_grpc_build::Config::new()
        .enable_server(true)
        .enable_client(true)
        .build(proto_files, proto_dirs)
        .unwrap_or_else(|e| panic!("protobuf compilation failed: {}", e));

    // Recompile protobufs only if any of the proto files changes.
    for file in proto_files {
        println!("cargo:rerun-if-changed={}", file);
    }
}
