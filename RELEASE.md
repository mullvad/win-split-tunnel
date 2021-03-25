# Making a release build

## One-time setup

These steps are performed on a trusted build machine.

Ensure the following software is installed:

1. `Visual Studio 2019` or later.
1. `Windows Driver Kit (WDK)` version `10.0.18362.1` or later.

Configure signing locally:

1. Install `Safenet Authentication Client`.
1. Register EV certificate in user store.

Configure signing in Microsoft partner portal:

1. Partner portal login page (use Azure account): [Partner Portal](https://partner.microsoft.com/en-us/dashboard/hardware)
1. Instructions for registering EV certificate with Microsoft: [Add or Update a code signing certificate](https://docs.microsoft.com/en-us/windows-hardware/drivers/dashboard/update-a-code-signing-certificate)
1. Instructions for configuring attestation signing: [Attestation signing a kernel driver for public release](https://docs.microsoft.com/en-us/windows-hardware/drivers/dashboard/attestation-signing-a-kernel-driver-for-public-release)

## Preparations

1. Ensure changelog is updated and includes all relevant changes.
1. Make appropriate changes to version number components in `src/version.h`. Push changes.
1. Create and push a signed Git tag which is named after the current updated version, e.g. `v1.2.3.4`.

## Building

1. Clone/pull updated driver code on trusted build machine.
1. Launch `Developer Command Prompt for VS 2019`.
1. `cd` into driver repository.
1. Run `build.bat <certificate-sha1-thumbprint>` to build and sign the driver.
1. Artifacts are prepared under `bin/dist/`:
    1. `bin/dist/legacy/` contains the final artifacts for Windows 7/8/8.1.
    1. `bin/dist/win10/` contains an intermediate driver package for Windows 10.
    1. `bin/dist/meta/` currently, only holds the shared PDB file.
1. Upload Windows 10 intermediate driver package (`mullvad-split-tunnel-amd64.cab`) to Microsoft for attestation signing.
1. Download attestation signed driver for Windows 10.

## Updating dependent repositories

1. In the `mullvadvpn-app-binaries` repository:
    1. Update legacy driver package in `x86_64-pc-windows-msvc/split-tunnel/legacy/`.
    1. Extract attestation signed driver and related files into `x86_64-pc-windows-msvc/split-tunnel/win10/`.
    1. Update driver PDB file in `x86_64-pc-windows-msvc/split-tunnel/meta/`.
    1. Merge file updates into `master`.
1. In the `mullvadvpn-app` repository:
    1. Update the `mullvadvpn-app-binaries` submodule reference.
    1. Merge reference update into `master`.
