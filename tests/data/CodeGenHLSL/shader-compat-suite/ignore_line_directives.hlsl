// RUN: %dxc -T lib_6_1 -Zi  -ignore-line-directives %s | FileCheck %s

// Make sure only 1 DIFile exist in debug info when NoLineDirectives is enabled.
// CHECK: !DIFile
// CHECK-NOT: !DIFile
// CHECK: ignore_line_directives.hlsl"
// CHECK: ignore_line_directives.hlsl"}
// CHECK-NOT: !DIFile

#line 0 "test.h"

RWStructuredBuffer<float2> buf0;
RWStructuredBuffer<float2> buf1;

#line 0 "test2.h"

void Store(bool bBufX, float2 v, uint idx) {
  RWStructuredBuffer<float2> buf = bBufX ? buf0: buf1;
  buf[idx] = v;
}