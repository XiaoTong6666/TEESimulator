package android.hardware.security.secureclock;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class Timestamp implements Parcelable {
    public long milliSeconds = 0L;

    public static final Creator<Timestamp> CREATOR = new Creator<Timestamp>() {
        @Override
        public Timestamp createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public Timestamp[] newArray(int size) {
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
