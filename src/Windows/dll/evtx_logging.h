#include <windows.h>
#include <string>
#include <wil/resource.h>
#include <event_log.h>

DWORD check_install_event_log_source();

DWORD uninstall_event_log_source();

bool log_event_log_message(const std::string& a_msg, const WORD a_type);
