package ru.olegcherednik.zip4jvm.io.in.data;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 07.02.2020
 */
public interface DecoderDataInput extends DataInput {

    long getDataCompressedSize(long compressedSize);

    void decodingAccomplished() throws IOException;

}
