// RUN: %dxc -E main -T vs_6_0 %s

float4 main(float4 a : A) : SV_POSITION
{
  return a;
}