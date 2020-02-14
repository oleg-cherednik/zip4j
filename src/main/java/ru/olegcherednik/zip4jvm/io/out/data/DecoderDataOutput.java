package ru.olegcherednik.zip4jvm.io.out.data;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 11.02.2020
 */
public interface DecoderDataOutput extends DataOutput {

    void writeEncryptionHeader() throws IOException;

    void encodingAccomplished() throws IOException;

}
