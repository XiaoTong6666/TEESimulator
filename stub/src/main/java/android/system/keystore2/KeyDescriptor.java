package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class KeyDescriptor implements Parcelable {
    public int domain;
    public long nspace;
    public String alias;
    public byte[] blob;

    public KeyDescriptor() {
    }

    protected KeyDescriptor(Parcel in) {
        readFromParcel(in);
    }

    public void readFromParcel(Parcel in) {
        domain = in.readInt();
        nspace = in.readLong();
        alias = in.readString();
        blob = in.createByteArray();
    }

    public static final Creator<KeyDescriptor> CREATOR = new Creator<KeyDescriptor>() {
        @Override
        public KeyDescriptor createFromParcel(Parcel in) {
            return new KeyDescriptor(in);
        }

        @Override
        public KeyDescriptor[] newArray(int size) {
            return new KeyDescriptor[size];
        }
    };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        dest.writeInt(domain);
        dest.writeLong(nspace);
        dest.writeString(alias);
        dest.writeByteArray(blob);
    }
}