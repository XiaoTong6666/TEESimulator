package android.os;

import androidx.annotation.NonNull;

public class ServiceSpecificException extends RuntimeException {
    public final int errorCode;

    public ServiceSpecificException(int errorCode) {
        this.errorCode = errorCode;
    }

    public ServiceSpecificException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    @NonNull
    @Override
    public String toString() {
        String message = getMessage();
        return "android.os.ServiceSpecificException: "
                + errorCode
                + (message != null ? ": " + message : "");
    }
}
