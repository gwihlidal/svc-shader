/* Mapping table




*/

pub trait ShaderLanguage {}

pub enum Format {
    Text,
    Binary,
    Hlsl,
    Glsl,
    Metal,
    Dxil,
    Dxbc,
    Spirv,
}

pub mod dxc;
pub mod fxc;
pub mod rga;
pub mod shaderc;
pub mod signing;
pub mod smolv;
pub mod spirv_as;
pub mod spirv_cross;
pub mod spirv_dis;
pub mod spirv_val;
