package android.system.keystore2;

import android.hardware.security.keymint.KeyParameter;
import android.os.Parcel;
import android.os.Parcelable;

public class Authorization implements Parcelable {
    public KeyParameter keyParameter;
    public int securityLevel = 0;
    public Authorization() {
    }
    protected Authorization(Parcel in) {
        keyParameter = in.readTypedObject(KeyParameter.CREATOR);
        securityLevel = in.readInt();
    }
    public static final Creator<Authorization> CREATOR = new Creator<Authorization>() {
        @Override
        public Authorization createFromParcel(Parcel in) {
            return new Authorization(in);
        }
        @Override
        public Authorization[] newArray(int size) {
            return new Authorization[size];
        }
    };
    @Override
    public int describeContents() {
        return 0;
    }
    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeTypedObject(keyParameter, flags);
        dest.writeInt(securityLevel);
    }
}