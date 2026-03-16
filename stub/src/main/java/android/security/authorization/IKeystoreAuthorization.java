package android.security.authorization;

import android.hardware.security.keymint.HardwareAuthToken;
import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;

public interface IKeystoreAuthorization extends IInterface {
    String DESCRIPTOR = "android.security.authorization.IKeystoreAuthorization";

    void addAuthToken(HardwareAuthToken authToken);

    abstract class Stub extends Binder implements IKeystoreAuthorization {
        public static final int TRANSACTION_addAuthToken = IBinder.FIRST_CALL_TRANSACTION + 0;
        public static final int TRANSACTION_onDeviceUnlocked = IBinder.FIRST_CALL_TRANSACTION + 1;
        public static final int TRANSACTION_onDeviceLocked = IBinder.FIRST_CALL_TRANSACTION + 2;
        public static final int TRANSACTION_onWeakUnlockMethodsExpired =
                IBinder.FIRST_CALL_TRANSACTION + 3;
        public static final int TRANSACTION_onNonLskfUnlockMethodsExpired =
                IBinder.FIRST_CALL_TRANSACTION + 4;
        public static final int TRANSACTION_getAuthTokensForCredStore =
                IBinder.FIRST_CALL_TRANSACTION + 5;
        public static final int TRANSACTION_getLastAuthTime = IBinder.FIRST_CALL_TRANSACTION + 6;

        public static IKeystoreAuthorization asInterface(IBinder binder) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public IBinder asBinder() {
            return this;
        }

        @Override
        public void addAuthToken(HardwareAuthToken authToken) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
