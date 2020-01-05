package ru.olegcherednik.zip4jvm.io.readers;

import ru.olegcherednik.zip4jvm.crypto.strong.DecryptionHeader;
import ru.olegcherednik.zip4jvm.crypto.strong.DecryptionInfo;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 11.10.2019
 */
public final class DecryptionHeaderReader implements Reader<DecryptionHeader> {

    private static final String MARKER = "DECRYPTION_INFO_HEADER";

    @Override
    public DecryptionHeader read(DataInput in) throws IOException {
        DecryptionHeader header = new DecryptionHeader();

        header.setIvSize(in.readWord());
        header.setIv(in.readBytes(header.getIvSize()));
        header.setSize(in.readDword());
        header.setDecryptionInfo(readDecryptionInfo(in, header.getSize()));

        return header;
    }

    @SuppressWarnings("ThrowFromFinallyBlock")
    private static DecryptionInfo readDecryptionInfo(DataInput in, long size) throws IOException {
        try {
            in.mark(MARKER);
            return new DecryptionInfoReader().read(in);
        } finally {
            if (in.getOffs() - in.getMark(MARKER) != size)
                throw new Zip4jvmException("DecryptionHeader size is incorrect");
        }
    }
}
