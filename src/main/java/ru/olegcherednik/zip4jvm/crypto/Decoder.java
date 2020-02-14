package ru.olegcherednik.zip4jvm.crypto;

import ru.olegcherednik.zip4jvm.io.in.data.DataInput;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 22.03.2019
 */
public interface Decoder {

    Decoder NULL = new NullDecoder();

    void decrypt(byte[] buf, int offs, int len);

    long getDataCompressedSize(long compressedSize);

    default void close(DataInput in) throws IOException {
        /* nothing to close */
    }

}
