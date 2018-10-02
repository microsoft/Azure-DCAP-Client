// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <curl.h>

__attribute__((constructor)) void _init()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
}
