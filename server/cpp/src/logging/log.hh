#pragma once
#include <seastar/util/log.hh>


namespace logging
{

extern seastar::logger log;

void init(
    const seastar::sstring _base_log_filename,
    const seastar::sstring _app_runtime_instance_uid
  );

class c_log_rotate final
{
public: // construction / destruction

  c_log_rotate(
      seastar::sstring _base_log_filename,
      seastar::sstring _app_runtime_instance_uid
    );

  ~c_log_rotate() = default;

public: // interface

  seastar::future<> run();

  void rotate_logs();

private: // members

  seastar::sstring m_base_log_filename       {};
  seastar::sstring m_app_runtime_instance_uid{};
  std::ofstream    m_logfile_output_stream   {};
};

extern std::unique_ptr<c_log_rotate> log_rotate;

} // namespace logging