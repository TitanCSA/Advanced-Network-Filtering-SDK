# Advanced Network Filtering SDK

WFP IPv4/IPv6 connection filtering with application-path, protocol, CIDR and port policies; native C++17 SDK and a Windows policy inspector.

**Microsoft-signed Windows x64 evaluation driver. One-hour demo per Windows kernel boot.**

[Download the Windows bundle](https://github.com/TitanCSA/Advanced-Network-Filtering-SDK/releases/tag/v0.1.0) | [API guide](docs/API.md) | [Scope and limits](docs/LIMITS.md) | [Validation](docs/VALIDATION.json)

## Install

1. Extract the complete Windows x64 release ZIP into a local folder.
2. Run `AdvancedNetworkSetup.exe` as administrator, or open an administrator terminal in that folder and run:

```powershell
.\AdvancedNetworkSetupConsole.exe /install
```

The installer contains the matching INF, Microsoft catalog and both driver binaries. It verifies the Microsoft publisher and catalog membership. No test mode or security-setting changes are required. Restart Windows if the installer requests it. Use `/uninstall` with the same installer to remove the product.

Run `TitanAdvancedNetwork.exe` to open the policy inspector. Start explicitly before observing traffic or applying rules.

## Use the native SDK

The release ZIP contains the C++17 SDK sources and examples. The CMake library target is `AdvancedNetwork`. Serialize calls on each SDK object and review the API limits before integrating.

```powershell
cmake -S . -B obj/Native -G "Visual Studio 17 2022" -A x64
cmake --build obj/Native --config Release
ctest --test-dir obj/Native -C Release --output-on-failure
```

This builds user-mode source. The private kernel source and signing material are not in this repository. Building an installer from source requires the matching signed `Driver` directory from the release, configured with `-DDRIVER_PACKAGE_DIRECTORY=ABSOLUTE_PATH_TO_DRIVER_FOLDER`. Without that package, use the official release installer for installation.

## Demo behavior

The 3,600-second budget begins at first activation and is shared by clients for the current Windows kernel boot. Sleep counts. Closing/reopening a client or reinstalling does not reset it. Use Windows **Restart** for a fresh boot; Fast Startup shutdown may preserve a kernel session. The common resident clock can require a restart during uninstall. There is no full-license activation path in this preview.

## Validation and limitations

The Microsoft-returned files were matched to the submitted INF and executable sections. The self-contained installer and SDK live tests passed on Windows 11 build 26100 with **Secure Boot enabled and test signing disabled**. Additional pre-sign tests used Driver Verifier and AddressSanitizer in an isolated VM. Signing is not WHQL certification or proof of absence of bugs. The full real-time 3,600-second expiry run for this product remains pending; accelerated expiry was tested separately before signing.

This is a scoped WFP component, not a complete VPN. Application paths are not cryptographic identities. Missing metadata can prevent application-specific matching. Rules are inactive until a client starts them, and expiry releases filtering policy.

Windows x64 is the tested architecture. Other Windows builds, hardware combinations and long-duration workloads require further qualification. No npm, NuGet, PyPI or other registry package is claimed by this release; the documented deliverable is the native C++ SDK in the download bundle.

## Commercial enquiries

For unrestricted versions or commercial/OEM deployment, contact **`titancsa`** on Discord. Availability and terms must be agreed separately; this repository does not claim that a production edition is already supplied.
