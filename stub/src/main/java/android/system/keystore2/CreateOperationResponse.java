package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

public class CreateOperationResponse implements Parcelable {

    public IKeystoreOperation iKeystoreOperation;
    public Authorization[] parameters;
    public Integer operationChallenge;
    public byte[] upgradedBlob;
    public CreateOperationResponse() {
    }

    protected CreateOperationResponse(Parcel in) {
        iKeystoreOperation = IKeystoreOperation.Stub.asInterface(in.readStrongBinder());
        parameters = in.createTypedArray(Authorization.CREATOR);
        if (in.readInt() == 0) {
            operationChallenge = null;
        } else {
            operationChallenge = in.readInt();
        }
        upgradedBlob = in.createByteArray();
    }

    public static final Creator<CreateOperationResponse> CREATOR = new Creator<CreateOperationResponse>() {
        @Override
        public CreateOperationResponse createFromParcel(Parcel in) {
            return new CreateOperationResponse(in);
        }

        @Override
        public CreateOperationResponse[] newArray(int size) {
            return new CreateOperationResponse[size];
        }
    };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeStrongBinder(iKeystoreOperation != null ? iKeystoreOperation.asBinder() : null);
        dest.writeTypedArray(parameters, flags);
        if (operationChallenge == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeInt(operationChallenge);
        }
        dest.writeByteArray(upgradedBlob != null ? upgradedBlob : new byte[0]);
    }
}