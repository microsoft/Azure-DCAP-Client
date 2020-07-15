# Azure Data Center Attestation Primitives (DCAP) Client



This library serves as a quoting data provider plugin for the
[Intel SGX Data Center Attestation Primitives (DCAP)](https://github.com/intel/SGXDataCenterAttestationPrimitives).
Specifically, the Intel DCAP library will search out and load provider plugins, such as the Azure DCAP
Client. This provider plugin is then used to fetch certain data files, such as platform certificates,
TCB structures, and revocation lists.

The Azure DCAP Client fetches artifacts from an Azure-internal caching service. The purpose of this
cache is to ensure that all Azure hosts always have the correct data available and local within
the Azure cloud.

The data serviced by the Azure cache are all Intel-originating, and are rooted to Intel CAs. The
cache serves simply to ensure that there are no external dependencies on Intel for workloads running
on Azure infrastructure.

# Building

## Linux

See [src/Linux/README.MD](src/Linux/README.MD).

## Windows

See [src/Windows/README.MD](src/Windows/README.MD).

# Implementation

The library builds the full URL of the artifacts served by the Azure-internal caching service from the parameters passed to the `sgx_ql_get_revocation_info_t` and `sgx_get_qe_identity_info_t` API calls. 

For the certificate chain associated with an Intel SGX quote, each CRL Distribution Point is wrapped into an Azure-specific URL before being fetched by the Azure-DCAP-Client library. For example, the well-known Intel SGX Root CA CRL endpoint (https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl) is served by the Azure-internal caching service at: https://global.acccache.azure.net/sgx/certificates/pckcrl?uri=https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl&api-version=API_VERSION (where `API_VERSION` specifies the current API version).

# Configuration

The Azure-DCAP-Client library uses the following environment variables if set:

* `AZDCAP_CACHE` - Represents the base directory where the library cache directory `.az-dcap-client` is created. The default value is `$HOME` in Linux and LocalLow in Windows.
* `AZDCAP_BASE_CERT_URL` and `AZDCAP_CLIENT_ID` - Used in conjunction to explicitly overwrite the default values for the PCK caching service. These should be used only for development purposes and they **must** not be used in any production environment.
* `AZDCAP_COLLATERAL_VERSION` - Used to specify the collateral version requested from the PCK caching service. Must be either'v1' or 'v2' if specified and defaults to 'v1' if unspecified.
* `AZDCAP_DEBUG_LOG_LEVEL` - Used to enable logging to stdout for debug purposes. Supported values are INFO, WARNING, and ERROR; any other values will fail silently. If a logging callback is set by the caller such as open enclave this setting will be ignored as the logging callback will have precedence. Log levels follow standard behavior: INFO logs everything, WARNING logs warnings and errors, and ERROR logs only errors. Default setting has logging off. These capatalized values are represented internally as strings.

# See Also

1. [Open Enclave](https://github.com/Microsoft/openenclave), a cross-platform library for authoring
   enclaves.

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Formatting

Prior to submitting pull requests, please run clang-format -i on your sources to ensure consistent
styling with the rules contained in `src/.clang-format`.
