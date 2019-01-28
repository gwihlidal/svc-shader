// RUN: %dxc -T lib_6_1 %s | FileCheck %s

// Verify no hang on incomplete array

// CHECK: %struct.Special = type { <4 x float>, [0 x i32] }
// CHECK: %"$Globals" = type { i32, %struct.Special }

typedef const int inta[];

// CHECK: @s_testa = internal unnamed_addr constant [3 x i32] [i32 1, i32 2, i32 3], align 4
static inta s_testa = {1, 2, 3};

int i;

struct Special {
  float4 member;
  inta a;
};

Special c_special;

static const Special s_special = { { 1, 2, 3, 4}, { 1, 2, 3 } };

// CHECK: define void
// CHECK: fn1
// @"\01?fn1@@YA?AV?$vector@M$03@@USpecial@@@Z"
float4 fn1(in Special in1: SEMANTIC_IN) : SEMANTIC_OUT {
  // CHECK: call %dx.types.CBufRet.i32 @dx.op.cbufferLoadLegacy.i32(
  // CHECK: i32 0)
  // CHECK: extractvalue
  // CHECK: , 0
  // CHECK: getelementptr
  // CHECK: load i32, i32*
  // CHECK: sitofp i32
  // CHECK: fadd float
  return in1.member + (float)s_testa[i];
}

// CHECK: define void
// CHECK: fn2
// @"\01?fn2@@YA?AV?$vector@M$03@@USpecial@@@Z"
float4 fn2(in Special in1: SEMANTIC_IN) : SEMANTIC_OUT {
  // s_special.a[i] is broken: it just assumes 0.
  return in1.member + (float)s_special.a[i];
}

// CHECK: define void
// CHECK: fn3
// @"\01?fn3@@YA?AV?$vector@M$03@@USpecial@@@Z"
float4 fn3(in Special in1: SEMANTIC_IN) : SEMANTIC_OUT {
  // CHECK: call %dx.types.CBufRet.i32 @dx.op.cbufferLoadLegacy.i32(
  // CHECK: i32 0)
  // CHECK: extractvalue
  // CHECK: , 0
  // CHECK: getelementptr
  // CHECK: load i32, i32*
  // CHECK: sitofp i32
  // CHECK: fadd float
  return in1.member + (float)in1.a[i];
}

// CHECK: define void
// CHECK: fn4
// @"\01?fn4@@YA?AV?$vector@M$03@@USpecial@@@Z"
float4 fn4(in Special in1: SEMANTIC_IN) : SEMANTIC_OUT {
  // CHECK: call %dx.types.CBufRet.i32 @dx.op.cbufferLoadLegacy.i32(
  // CHECK: i32 0)
  // CHECK: extractvalue
  // CHECK: , 0
  // CHECK: add
  // CHECK: call %dx.types.CBufRet.i32 @dx.op.cbufferLoadLegacy.i32(
  // CHECK: extractvalue
  // CHECK: , 0
  // CHECK: sitofp i32
  // CHECK: fadd float
  return in1.member + c_special.a[i];
}
