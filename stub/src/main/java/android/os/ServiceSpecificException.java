package android.os;

import androidx.annotation.NonNull;

public class ServiceSpecificException extends RuntimeException {
    public final int errorCode;

    public ServiceSpecificException(int errorCode) {
        this.errorCode = errorCode;
        throw new UnsupportedOperationException("STUB!");
    }

    public ServiceSpecificException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
        throw new UnsupportedOperationException("STUB!");
    }

    @NonNull
    @Override
    public String toString() {
        throw new UnsupportedOperationException("STUB!");
    }
}
