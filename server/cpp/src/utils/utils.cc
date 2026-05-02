#include "utils/utils.hh"


namespace utils
{

std::string generate_random_string(
    const std::size_t _length
  )
{
  constexpr std::string_view RANDOM_SYMBOLS{ "0123456789abcdefghijklmnopqrstuvwxyz" };

  std::string random_string{};
  random_string.reserve(_length);

  while (random_string.length() < _length)
  {
    const auto random_idx = generate_random_value<std::size_t>(0, RANDOM_SYMBOLS.length() - 1);
    random_string += RANDOM_SYMBOLS[random_idx];
  }

  return random_string;
}

} // namespace utils