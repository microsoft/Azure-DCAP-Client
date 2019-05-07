// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef UNIT_TEST_H
#define UNIT_TEST_H

#undef NDEBUG // ensure that asserts are never compiled out
#include <cassert>

#define TEST_START() printf("---------\n%s\n", __FUNCTION__)
#define TEST_PASSED() printf("%s Passed\n", __FUNCTION__);

#endif