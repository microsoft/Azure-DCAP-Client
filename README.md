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

## CI
   Pull request will be run againt OpenEnclave repo as part this repo's CI test process

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
