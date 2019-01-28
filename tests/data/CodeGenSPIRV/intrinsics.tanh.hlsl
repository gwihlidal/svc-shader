// Run: %dxc -T vs_6_0 -E main

// According to HLSL reference:
// The 'tanh' function can only operate on float, vector of float, and matrix of float.

// CHECK:      [[glsl:%\d+]] = OpExtInstImport "GLSL.std.450"

void main() {
  float result;
  float2 result2;
  float3 result3;
  float4 result4;
  float3x2 result3x2;

// CHECK:      [[a:%\d+]] = OpLoad %float %a
// CHECK-NEXT: [[tanh_a:%\d+]] = OpExtInst %float [[glsl]] Tanh [[a]]
// CHECK-NEXT: OpStore %result [[tanh_a]]
  float a;
  result = tanh(a);

// CHECK-NEXT: [[b:%\d+]] = OpLoad %float %b
// CHECK-NEXT: [[tanh_b:%\d+]] = OpExtInst %float [[glsl]] Tanh [[b]]
// CHECK-NEXT: OpStore %result [[tanh_b]]
  float1 b;
  result = tanh(b);

// CHECK-NEXT: [[c:%\d+]] = OpLoad %v3float %c
// CHECK-NEXT: [[tanh_c:%\d+]] = OpExtInst %v3float [[glsl]] Tanh [[c]]
// CHECK-NEXT: OpStore %result3 [[tanh_c]]
  float3 c;
  result3 = tanh(c);

// CHECK-NEXT: [[d:%\d+]] = OpLoad %float %d
// CHECK-NEXT: [[tanh_d:%\d+]] = OpExtInst %float [[glsl]] Tanh [[d]]
// CHECK-NEXT: OpStore %result [[tanh_d]]
  float1x1 d;
  result = tanh(d);

// CHECK-NEXT: [[e:%\d+]] = OpLoad %v2float %e
// CHECK-NEXT: [[tanh_e:%\d+]] = OpExtInst %v2float [[glsl]] Tanh [[e]]
// CHECK-NEXT: OpStore %result2 [[tanh_e]]
  float1x2 e;
  result2 = tanh(e);

// CHECK-NEXT: [[f:%\d+]] = OpLoad %v4float %f
// CHECK-NEXT: [[tanh_f:%\d+]] = OpExtInst %v4float [[glsl]] Tanh [[f]]
// CHECK-NEXT: OpStore %result4 [[tanh_f]]
  float4x1 f;
  result4 = tanh(f);

// CHECK-NEXT: [[g:%\d+]] = OpLoad %mat3v2float %g
// CHECK-NEXT: [[g_row0:%\d+]] = OpCompositeExtract %v2float [[g]] 0
// CHECK-NEXT: [[tanh_g_row0:%\d+]] = OpExtInst %v2float [[glsl]] Tanh [[g_row0]]
// CHECK-NEXT: [[g_row1:%\d+]] = OpCompositeExtract %v2float [[g]] 1
// CHECK-NEXT: [[tanh_g_row1:%\d+]] = OpExtInst %v2float [[glsl]] Tanh [[g_row1]]
// CHECK-NEXT: [[g_row2:%\d+]] = OpCompositeExtract %v2float [[g]] 2
// CHECK-NEXT: [[tanh_g_row2:%\d+]] = OpExtInst %v2float [[glsl]] Tanh [[g_row2]]
// CHECK-NEXT: [[tanh_matrix:%\d+]] = OpCompositeConstruct %mat3v2float [[tanh_g_row0]] [[tanh_g_row1]] [[tanh_g_row2]]
// CHECK-NEXT: OpStore %result3x2 [[tanh_matrix]]
  float3x2 g;
  result3x2 = tanh(g);
}
