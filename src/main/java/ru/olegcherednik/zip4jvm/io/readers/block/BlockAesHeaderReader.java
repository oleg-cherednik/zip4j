package ru.olegcherednik.zip4jvm.io.readers.block;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.aes.AesEngine;
import ru.olegcherednik.zip4jvm.crypto.aes.AesStrength;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.block.crypto.AesEncryptionHeaderBlock;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;

import static ru.olegcherednik.zip4jvm.crypto.aes.AesEngine.MAC_SIZE;
import static ru.olegcherednik.zip4jvm.crypto.aes.AesEngine.PASSWORD_CHECKSUM_SIZE;

/**
 * @author Oleg Cherednik
 * @since 23.10.2019
 */
@RequiredArgsConstructor
public class BlockAesHeaderReader implements Reader<AesEncryptionHeaderBlock> {

    private final AesStrength strength;
    private final long compressedSize;

    @Override
    public AesEncryptionHeaderBlock read(DataInput in) throws IOException {
        AesEncryptionHeaderBlock block = new AesEncryptionHeaderBlock();
        block.getSalt().calc(in, () -> in.readBytes(strength.saltLength()));
        block.getPasswordChecksum().calc(in, () -> in.readBytes(PASSWORD_CHECKSUM_SIZE));
        in.skip(AesEngine.getDataCompressedSize(compressedSize, strength.saltLength()));
        block.getMac().calc(in, () -> in.readBytes(MAC_SIZE));
        return block;
    }

}
