package org.signal.libsignal.protocol.state;

import org.signal.libsignal.protocol.InvalidKeyIdException;

public interface KyberPreKeyStore {
    KyberPreKeyRecord loadKyberPreKey(int preKeyId) throws InvalidKeyIdException;
    void storeKyberPreKey(int preKeyId, KyberPreKeyRecord record);
    boolean containsKyberPreKey(int preKeyId);
    void removeKyberPreKey(int preKeyId);
}
