#include "core/core.hh"
#include "app_state.hh"


//
// construction / destruction
//

t_core::t_core(
    t_app_state& _app_state
  ):
  m_app_state{ _app_state }
{
  // empty
}
