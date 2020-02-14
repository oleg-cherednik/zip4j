package ru.olegcherednik.zip4jvm.io.readers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.aes.AesStrength;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.AesExtraFieldRecord;
import ru.olegcherednik.zip4jvm.model.Charsets;
import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 14.04.2019
 */
@RequiredArgsConstructor
public final class AesExtraDataRecordReader implements Reader<AesExtraFieldRecord> {

    private final int size;

    @Override
    public AesExtraFieldRecord read(DataInput in) throws IOException {
        int versionNumber = in.readWord();
        String vendor = in.readString(2, Charsets.UTF_8);
        AesStrength strength = AesStrength.parseValue(in.readByte());
        CompressionMethod compressionMethod = CompressionMethod.parseCode(in.readWord());

        return AesExtraFieldRecord.builder()
                                  .dataSize(size)
                                  .versionNumber(versionNumber)
                                  .vendor(vendor)
                                  .strength(strength)
                                  .compressionMethod(compressionMethod).build();
    }

    @Override
    public String toString() {
        return String.format("AES (0x%04X)", AesExtraFieldRecord.SIGNATURE);
    }

}
