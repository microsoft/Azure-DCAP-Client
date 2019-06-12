// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifdef __LINUX__
extern void LocalCacheTests();
#endif

extern void QuoteProvTests();

int main()
{
    
#ifdef __LINUX__
    LocalCacheTests();
#endif

    QuoteProvTests();
    return 0;
}
