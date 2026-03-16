package android.hardware.security.keymint;

import android.hardware.security.secureclock.Timestamp;
import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class HardwareAuthToken implements Parcelable {
    public long challenge = 0L;
    public long userId = 0L;
    public long authenticatorId = 0L;
    public int authenticatorType = 0;
    public Timestamp timestamp;
    public byte[] mac;

    public static final Creator<HardwareAuthToken> CREATOR = new Creator<HardwareAuthToken>() {
        @Override
        public HardwareAuthToken createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public HardwareAuthToken[] newArray(int size) {
            throw new UnsupportedOperationException("STUB!");
        }
    };

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public void writeToParcel(@NonNull Parcel parcel, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }
}
