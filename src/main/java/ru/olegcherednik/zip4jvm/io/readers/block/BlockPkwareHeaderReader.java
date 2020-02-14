package ru.olegcherednik.zip4jvm.io.readers.block;

import ru.olegcherednik.zip4jvm.crypto.pkware.PkwareHeader;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.block.crypto.PkwareEncryptionHeaderBlock;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 24.10.2019
 */
public class BlockPkwareHeaderReader implements Reader<PkwareEncryptionHeaderBlock> {

    @Override
    public PkwareEncryptionHeaderBlock read(DataInput in) throws IOException {
        PkwareEncryptionHeaderBlock encryptionHeader = new PkwareEncryptionHeaderBlock();
        encryptionHeader.calc(in, () -> in.readBytes(PkwareHeader.SIZE));
        return encryptionHeader;
    }
}
