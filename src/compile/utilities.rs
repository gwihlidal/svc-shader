use crate::proto::drivers;

pub fn parse_dxc_profile(input: &str) -> drivers::dxc::TargetProfile {
    match input {
        "ps" => drivers::dxc::TargetProfile::Pixel,
        "vs" => drivers::dxc::TargetProfile::Vertex,
        "cs" => drivers::dxc::TargetProfile::Compute,
        "gs" => drivers::dxc::TargetProfile::Geometry,
        "ds" => drivers::dxc::TargetProfile::Domain,
        "hs" => drivers::dxc::TargetProfile::Hull,
        // TODO: "task" => drivers::dxc::TargetProfile::Task,
        // TODO: "mesh" => drivers::dxc::TargetProfile::Mesh,
        "rgen" => drivers::dxc::TargetProfile::RayGen,
        "isec" => drivers::dxc::TargetProfile::RayIntersection,
        "chit" => drivers::dxc::TargetProfile::RayClosestHit,
        "ahit" => drivers::dxc::TargetProfile::RayAnyHit,
        "miss" => drivers::dxc::TargetProfile::RayMiss,
        // TODO: "call" => drivers::dxc::TargetProfile::Library,
        _ => {
            println!("Unknown dxc profile: {}", input);
            unimplemented!();
        }
    }
}

pub fn parse_dxc_profile_version(
    input: &str,
) -> (drivers::dxc::TargetProfile, drivers::dxc::TargetVersion) {
    let parts = input.split('_').collect::<Vec<&str>>();
    if parts.len() == 3 {
        let profile = parse_dxc_profile(&parts[0]);
        let version = match parts[1] {
            "6" => match parts[2] {
                "0" => drivers::dxc::TargetVersion::V60,
                "1" => drivers::dxc::TargetVersion::V61,
                "2" => drivers::dxc::TargetVersion::V62,
                "3" => drivers::dxc::TargetVersion::V63,
                "4" => drivers::dxc::TargetVersion::V64,
                _ => unimplemented!(),
            },
            _ => unimplemented!(),
        };
        (profile, version)
    } else {
        let profile = parse_dxc_profile(input);
        match profile {
            drivers::dxc::TargetProfile::RayGen
            | drivers::dxc::TargetProfile::RayIntersection
            | drivers::dxc::TargetProfile::RayClosestHit
            | drivers::dxc::TargetProfile::RayAnyHit
            | drivers::dxc::TargetProfile::RayMiss => (profile, drivers::dxc::TargetVersion::V63),
            _ => (profile, drivers::dxc::TargetVersion::V60),
        }
    }
}

pub fn parse_glslc_profile(input: &str) -> drivers::shaderc::TargetProfile {
    match input {
        "ps" => drivers::shaderc::TargetProfile::Pixel,
        "vs" => drivers::shaderc::TargetProfile::Vertex,
        "cs" => drivers::shaderc::TargetProfile::Compute,
        "gs" => drivers::shaderc::TargetProfile::Geometry,
        "ds" => drivers::shaderc::TargetProfile::Domain,
        "hs" => drivers::shaderc::TargetProfile::Hull,
        "task" => drivers::shaderc::TargetProfile::Task,
        "mesh" => drivers::shaderc::TargetProfile::Mesh,
        "rgen" => drivers::shaderc::TargetProfile::RayGen,
        "isec" => drivers::shaderc::TargetProfile::RayIntersection,
        "chit" => drivers::shaderc::TargetProfile::RayClosestHit,
        "ahit" => drivers::shaderc::TargetProfile::RayAnyHit,
        "miss" => drivers::shaderc::TargetProfile::RayMiss,
        //"call" => , // TODO
        _ => {
            println!("Unknown glslc profile: {}", input);
            unimplemented!();
        }
    }
}

pub fn parse_glslc_profile_version(
    input: &str,
) -> (
    drivers::shaderc::TargetProfile,
    drivers::shaderc::VulkanVersion,
) {
    let parts = input.split('_').collect::<Vec<&str>>();
    if parts.len() == 3 {
        let profile = parse_glslc_profile(&parts[0]);
        let version = match parts[1] {
            "6" => match parts[2] {
                "0" => drivers::shaderc::VulkanVersion::Vulkan10,
                _ => drivers::shaderc::VulkanVersion::Vulkan11,
            },
            _ => drivers::shaderc::VulkanVersion::Vulkan10,
        };
        (profile, version)
    } else {
        let profile = parse_glslc_profile(input);
        (profile, drivers::shaderc::VulkanVersion::Vulkan10)
    }
}
