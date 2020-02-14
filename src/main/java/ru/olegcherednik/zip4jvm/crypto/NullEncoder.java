package ru.olegcherednik.zip4jvm.crypto;

import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 09.08.2019
 */
final class NullEncoder implements Encoder {

    @Override
    public void writeEncryptionHeader(DataOutput out) throws IOException {
        /* nothing to write */
    }

    @Override
    public void encrypt(byte[] buf, int offs, int len) {
        /* nothing to encrypt */
    }

    @Override
    public String toString() {
        return "<null>";
    }

}
