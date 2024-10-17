package org.signal.libsignal.protocol.state;

import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.util.ByteUtil;

public class KyberPreKeyRecord {

    private final int id;
    private final byte[] publicKey;
    private final byte[] privateKey;

    public KyberPreKeyRecord(int id, byte[] publicKey, byte[] privateKey) {
        this.id = id;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public KyberPreKeyRecord(byte[] serialized) throws InvalidMessageException {
        if (serialized.length < 4) {
            throw new InvalidMessageException("Invalid serialized KyberPreKeyRecord");
        }

        this.id = ByteUtil.byteArrayToInt(serialized, 0);
        int publicKeyLength = ByteUtil.byteArrayToInt(serialized, 4);
        int privateKeyLength = ByteUtil.byteArrayToInt(serialized, 8);

        if (serialized.length < 12 + publicKeyLength + privateKeyLength) {
            throw new InvalidMessageException("Invalid serialized KyberPreKeyRecord");
        }

        this.publicKey = ByteUtil.copyFrom(serialized, 12, publicKeyLength);
        this.privateKey = ByteUtil.copyFrom(serialized, 12 + publicKeyLength, privateKeyLength);
    }

    public int getId() {
        return id;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public byte[] serialize() {
        byte[] idBytes = ByteUtil.intToByteArray(id);
        byte[] publicKeyLengthBytes = ByteUtil.intToByteArray(publicKey.length);
        byte[] privateKeyLengthBytes = ByteUtil.intToByteArray(privateKey.length);

        return ByteUtil.combine(idBytes, publicKeyLengthBytes, privateKeyLengthBytes, publicKey, privateKey);
    }
}
