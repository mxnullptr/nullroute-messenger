#pragma once
#include <random>


namespace utils
{

template<typename T = uint64_t>
requires std::integral<T>
T generate_random_value(
    const T _min = std::numeric_limits<T>::min(),
    const T _max = std::numeric_limits<T>::max()
  )
{
  std::uniform_int_distribution<T> distribution(_min, _max);

  static std::random_device random_device;
  static std::mt19937       random_number_generator{ random_device() };

  return distribution(random_number_generator);
}

// ------------------------------------------------------------------------------------------------------------------ //

template<typename T = double>
requires std::floating_point<T>
T generate_random_value(
    const T _min,
    const T _max
  )
{
  std::uniform_real_distribution<T> distribution(_min, _max);

  static std::random_device random_device;
  static std::mt19937       random_number_generator{ random_device() };

  return distribution(random_number_generator);
}

// ------------------------------------------------------------------------------------------------------------------ //

std::string generate_random_string(
    const std::size_t _length
  );

} // namespace utils