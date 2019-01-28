// Run: %dxc -T cs_6_0 -E main

// Execution scope : Workgroup = 0x2 = 2
// Memory scope : Device = 0x1 = 1
// Semantics: ImageMemory | AtomicCounterMemory | UniformMemory | WorkgroupMemory | AcquireRelease = 0x800 | 0x400 | 0x40 | 0x100 | 0x8 = 3400

void main() {
// CHECK: OpControlBarrier %uint_2 %uint_1 %uint_3400
  AllMemoryBarrierWithGroupSync();
}
