#pragma once
#include <x86intrin.h>


namespace utils
{

inline uint64_t rdtsc_begin()
{
  _mm_lfence();
  uint64_t tsc = __rdtsc();
  _mm_lfence();

  return tsc;
}

// ------------------------------------------------------------------------------------------------------------------ //

inline uint64_t rdtsc_end()
{
  uint32_t cpuid;
  uint64_t tsc = __rdtscp(&cpuid);
  _mm_lfence();

  return tsc;
}

} // namespace utils