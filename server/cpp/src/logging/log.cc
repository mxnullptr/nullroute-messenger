#include "logging/log.hh"
#include <iostream>
#include <seastar/core/loop.hh>
#include <seastar/core/sleep.hh>


using namespace std::chrono_literals;


namespace logging
{

seastar::logger log("nullroute-server");

std::unique_ptr<c_log_rotate> log_rotate{ nullptr };

//
// types
//

void init(
    const seastar::sstring _base_log_filename,
    const seastar::sstring _app_runtime_instance_uid
  )
{
  log_rotate = std::make_unique<c_log_rotate>(
      std::move(_base_log_filename),
      std::move(_app_runtime_instance_uid)
    );

  log_rotate->rotate_logs();
}

// ------------------------------------------------------------------------------------------------------------------ //

c_log_rotate::c_log_rotate(
    seastar::sstring _base_log_filename,
    seastar::sstring _app_runtime_instance_uid
  ):
  m_base_log_filename       { std::move(_base_log_filename) },
  m_app_runtime_instance_uid{ std::move(_app_runtime_instance_uid)}
{
  // empty
}

// ------------------------------------------------------------------------------------------------------------------ //

seastar::future<> c_log_rotate::run()
{
  return seastar::repeat([this] {
    const auto current_timestamp          = std::chrono::system_clock::now();
    const auto next_hour_timestamp        = std::chrono::ceil<std::chrono::hours>(current_timestamp);
    const auto sleep_to_the_next_rotation = next_hour_timestamp - current_timestamp;

    return seastar::sleep(sleep_to_the_next_rotation).then([this]() {
      rotate_logs();
      return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::no);
    });
  });
}

// ------------------------------------------------------------------------------------------------------------------ //

void c_log_rotate::rotate_logs()
{
  if (m_logfile_output_stream.is_open())
    m_logfile_output_stream.close();

  const auto current_timestamp = std::chrono::system_clock::now();
  const auto time_data         = std::chrono::system_clock::to_time_t(current_timestamp);

  std::stringstream output;
  output << std::put_time(std::localtime(&time_data), "%d%b%H");
  const auto timestamp_str = output.str();

  const auto log_filename = seastar::format("{}-{}-{}.log", m_base_log_filename, timestamp_str, m_app_runtime_instance_uid);

  m_logfile_output_stream.open(log_filename.c_str(), std::ios::out | std::ios::app);

  seastar::logger::set_with_color(false);
  seastar::logger::set_ostream(m_logfile_output_stream);
}

} // namespace logging