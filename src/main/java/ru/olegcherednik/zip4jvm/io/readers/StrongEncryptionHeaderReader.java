package ru.olegcherednik.zip4jvm.io.readers;

import ru.olegcherednik.zip4jvm.crypto.strong.EncryptionAlgorithm;
import ru.olegcherednik.zip4jvm.crypto.strong.StrongEncryptionHeader;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 10.10.2019
 */
final class StrongEncryptionHeaderReader implements Reader<StrongEncryptionHeader> {

    @Override
    public StrongEncryptionHeader read(DataInput in) throws IOException {
        int size = in.readWord();
        int format = in.readWord();
        EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.parseCode(in.readWord());
        int bitLength = in.readWord();
        int flags = in.readWord();
        byte[] certData = in.readBytes(size - 8);

        return StrongEncryptionHeader.builder()
                                     .size(size)
                                     .format(format)
                                     .encryptionAlgorithm(encryptionAlgorithm)
                                     .bitLength(bitLength)
                                     .flags(flags)
                                     .certData(certData).build();
    }
}
