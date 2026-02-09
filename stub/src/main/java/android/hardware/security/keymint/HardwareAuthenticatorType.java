package android.hardware.security.keymint;

public @interface HardwareAuthenticatorType {
    int NONE = 0;
    int PASSWORD = 1;
    int FINGERPRINT = 2;
    int ANY = -1;
}
