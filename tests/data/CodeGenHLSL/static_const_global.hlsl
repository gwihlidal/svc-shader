// RUN: %dxc -T lib_6_1 %s | FileCheck %s

// Make sure ST is removed
// CHECK-NOT: @ST

cbuffer A {
  float a;
  int b;
}

const static struct {
  float a;
  int b;
}  ST = { a, b };

float4 test() {
  return ST.a + ST.b;
}

float test2() {
  return ST.a - ST.b;
}
