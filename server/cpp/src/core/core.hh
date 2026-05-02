#pragma once
#include <seastar/core/future.hh>


struct t_app_state;


struct t_core final
{
public: // members

  t_app_state& m_app_state;

public: // construction / destruction

  t_core(
      t_app_state& _app_state
    );

  ~t_core() = default;

public: // interface

  seastar::future<> run()
  {
    return seastar::make_ready_future<>();
  }
};