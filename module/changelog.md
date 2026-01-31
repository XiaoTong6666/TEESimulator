## 🎉 TEESimulator v3.1: Legacy Support & Resilience

This release marks a significant step forward in our mission, focusing on breathing life into devices with **broken TEEs** and extending full support to older Android versions (**Android 10–12**).

### 🛡️ Enhanced Keystore2 Emulation
We have implemented critical APIs to support devices where the hardware TEE is broken or for applications configured to use key generation mode. These improvements directly address detection vectors identified in v3.0:

*   **✅ Full Crypto Operations (`createOperation`)**: The simulator now correctly handles `SIGN`, `VERIFY`, `ENCRYPT`, and `DECRYPT` purposes for software-generated keys.
*   **🔗 Certificate Chain Updates (`updateSubcomponent`)**: Added support for applications updating the certificate chain of virtual keys (e.g., via `KeyStore.setKeyEntry`).
*   **📋 Enumeration Support (`listEntries`)**: Generated keys are now properly visible in enumeration APIs like `KeyStore.aliases()`, thanks to the implementation of `listEntries` and `listEntriesBatched`.

### 🔧 Compatibility & Stability
We’ve ironed out crashes and architecture-specific bugs to ensure a smooth experience across more devices:

*   **Android 10**: Fixed a crash caused by the missing `waitForService` method.
*   **Android 11**: Implemented environment initialization and daemon UID spoofing to successfully bypass keystore generation permission checks.
*   **ARM 32-bit (Android 12)**: Resolved `ptrace` compatibility issues by falling back to `PTRACE_GETREGS` and `PTRACE_SETREGS`.
*   **x86_64 Emulators**: Enforced respect for the stack pointer "red zone" and added a staging fallback mechanism for file descriptor transfering of `libTEESimulator.so`.

### 🚀 The Road Ahead

We are aware of the remaining detection vectors (see the issues list) and have clear solutions mapped out for the next release.

Google's aggressive push for **Remote Key Provisioning (RKP)** and the drying up of leaked keyboxes is **not** the end for TEESimulator. Our ultimate goal remains unchanged: defeating Keystore attestation **without relying on a valid keybox**.

We are inching closer to this milestone, but the fight for device freedom is complex and resource-intensive. Your patience and support (both time and financial) are vital as we conquer these new challenges.
