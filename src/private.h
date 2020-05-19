// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef PRIVATE_H
#define PRIVATE_H

#include "dcap_provider.h"
#include <string>

extern sgx_ql_logging_function_t logger_callback;

///////////////////////////////////////////////////////////////////////////////
// Various internal functions which are not exported.
///////////////////////////////////////////////////////////////////////////////
void log(sgx_ql_log_level_t level, const char* fmt, ...);
void log_message(sgx_ql_log_level_t level, const char* message);
#endif
