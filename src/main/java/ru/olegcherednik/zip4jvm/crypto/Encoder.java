package ru.olegcherednik.zip4jvm.crypto;

import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 22.03.2019
 */
public interface Encoder {

    Encoder NULL = new NullEncoder();

    void writeEncryptionHeader(DataOutput out) throws IOException;

    void encrypt(byte[] buf, int offs, int len);

    default void close(DataOutput out) throws IOException {
        /* nothing to close */
    }

}
