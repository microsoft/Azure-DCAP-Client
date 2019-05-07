# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
    
function fetch_from_intel_github
{
    Param ([string] $path)
    $file = "ext/intel/" + $(Split-Path $path -Leaf)
    if (-Not (Test-Path $file))
    {
        $uri = "https://raw.githubusercontent.com/intel/" + $path
        Write-Host "Fetching $file from Intel(R) GitHub."
        Invoke-WebRequest -OutFile $file -Uri $uri
    }
}

mkdir -Force ext/intel | Out-Null

fetch_from_intel_github -path SGXDataCenterAttestationPrimitives/c27fe49f499104eda9364c7b048aff290fa00766/QuoteGeneration/psw/quote_wrapper/common/inc/sgx_ql_lib_common.h
fetch_from_intel_github -path linux-sgx/1ccf25b64abd1c2eff05ead9d14b410b3c9ae7be/common/inc/sgx_report.h
fetch_from_intel_github -path linux-sgx/1ccf25b64abd1c2eff05ead9d14b410b3c9ae7be/common/inc/sgx_key.h
fetch_from_intel_github -path linux-sgx/1ccf25b64abd1c2eff05ead9d14b410b3c9ae7be/common/inc/sgx_attributes.h

Invoke-WebRequest -OutFile curl-ca-bundle.crt -Uri https://curl.haxx.se/ca/cacert.pem
