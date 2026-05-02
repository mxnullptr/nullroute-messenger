#pragma once
#include <memory>
#include "core/core.hh"


struct t_app_state final
{
public: // members

  std::unique_ptr<t_core> core{ nullptr };
};