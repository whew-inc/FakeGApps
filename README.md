# FakeGApps
Used in combination with [MicroG](https://microg.org/) to enable Google Cloud Messaging (GCM) and much more without proprietary Google Play Services.

Supports Android 4.0 - 16

## Prerequisites
- **MicroG** installed (I personally recommend [nift4's microG Installer Revived](https://github.com/nift4/microg_installer_revived) to install MicroG)
- Working **Xposed Framework** installation (Ex. [LSPosed](https://github.com/LSPosed/LSPosed), [EdXposed](https://github.com/ElderDrivers/EdXposed), [Dreamland](https://github.com/canyie/Dreamland) ...)

## Installation
Install the APK from the [releases section](https://github.com/whew-inc/FakeGApps/releases) and enable it in your Xposed framework provider. Make sure to enable FakeGapps in your Xposed framework provider.

Reboot your device. If everything went right, MicroG should now have a checkmark next to "System spoofs signature" in its self-check.

[FakeGApps is also available in the LSPosed repository](https://modules.lsposed.org/module/inc.whew.android.fakegapps)
