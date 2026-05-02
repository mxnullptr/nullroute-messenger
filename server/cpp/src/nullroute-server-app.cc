#include <iostream>
#include "app_state.hh"
#include "logging/log.hh"
#include "utils/utils.hh"
#include <seastar/core/app-template.hh>
#include <seastar/core/when_all.hh>


seastar::future<> application()
{
  constexpr auto k_app_runtime_instance_uid_length = 5;
  const auto     app_runtime_instance_uid          = utils::generate_random_string(k_app_runtime_instance_uid_length);

  logging::init("nullroute-server", app_runtime_instance_uid);
  logging::log.info("[ok] application >>> runtime instance uid {}", app_runtime_instance_uid);

  auto app_state = seastar::make_lw_shared<t_app_state>();

  app_state->core = std::make_unique<t_core>(*app_state);

  return seastar::do_with(std::move(app_state), [](auto app_state) {
    return seastar::when_all(
      app_state->core->run()
    ).then([](auto futures) {
      auto& [ core_result ] = futures;

      core_result.get();

      logging::log.info("[ok] done");
      return seastar::make_ready_future<>();
    });
  });
}

// ------------------------------------------------------------------------------------------------------------------ //

int main(
    int    _argc,
    char** _argv
  )
{
  try
  {
    seastar::app_template app;

    app.run(_argc, _argv, [] {
      return application();
    });
  }
  catch (...)
  {
    std::cerr << "couldn't start application: " << std::current_exception() << "\n";
    return -1;
  }

  return 0;
}
