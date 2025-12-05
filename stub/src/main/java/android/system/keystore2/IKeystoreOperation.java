package android.system.keystore2;

import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

public interface IKeystoreOperation extends IInterface {

    /**
     * 定义Transaction Code，通常AIDL生成的顺序就是下面这样，要是没对齐，调用可能会乱.
     * 手写Stub需要保证Client和Server两头能对齐.
     * App端用的系统的Proxy，所以匹配系统的Transaction Code.
     * Android 12+的IKeystoreOperation.aidl顺序大概长这样：
     * void updateAad(in byte[] aadInput);
     * byte[] update(in byte[] input);
     * byte[] finish(in byte[] input, in byte[] signature);
     * void abort();*/

    int TRANSACTION_updateAad = IBinder.FIRST_CALL_TRANSACTION + 0;
    int TRANSACTION_update = IBinder.FIRST_CALL_TRANSACTION + 1;
    int TRANSACTION_finish = IBinder.FIRST_CALL_TRANSACTION + 2;
    int TRANSACTION_abort = IBinder.FIRST_CALL_TRANSACTION + 3;

    byte[] update(byte[] input) throws RemoteException;

    void updateAad(byte[] aad) throws RemoteException;

    byte[] finish(byte[] input, byte[] signature) throws RemoteException;

    void abort() throws RemoteException;

    public static abstract class Stub extends Binder implements IKeystoreOperation {
        private static final String DESCRIPTOR = "android.system.keystore2.IKeystoreOperation";

        public Stub() {
            this.attachInterface(this, DESCRIPTOR);
        }

        public static IKeystoreOperation asInterface(IBinder obj) {
            if ((obj == null)) {
                return null;
            }
            IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
            if (((iin != null) && (iin instanceof IKeystoreOperation))) {
                return ((IKeystoreOperation) iin);
            }
            //服务端，不需要作为Client去调用
            return null;
        }

        @Override
        public IBinder asBinder() {
            return this;
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            switch (code) {
                case INTERFACE_TRANSACTION: {
                    reply.writeString(DESCRIPTOR);
                    return true;
                }
                case TRANSACTION_updateAad: {
                    data.enforceInterface(DESCRIPTOR);
                    byte[] _arg0 = data.createByteArray();
                    this.updateAad(_arg0);
                    reply.writeNoException();
                    return true;
                }
                case TRANSACTION_update: {
                    data.enforceInterface(DESCRIPTOR);
                    byte[] _arg0 = data.createByteArray();
                    byte[] _result = this.update(_arg0);
                    reply.writeNoException();
                    reply.writeByteArray(_result);
                    return true;
                }

                case TRANSACTION_finish: {
                    data.enforceInterface(DESCRIPTOR);
                    byte[] _arg0 = data.createByteArray();
                    byte[] _arg1 = data.createByteArray();
                    byte[] _result = this.finish(_arg0, _arg1);
                    reply.writeNoException();
                    reply.writeByteArray(_result);
                    return true;
                }
                case TRANSACTION_abort: {
                    data.enforceInterface(DESCRIPTOR);
                    this.abort();
                    reply.writeNoException();
                    return true;
                }
            }
            return super.onTransact(code, data, reply, flags);
        }
    }
}