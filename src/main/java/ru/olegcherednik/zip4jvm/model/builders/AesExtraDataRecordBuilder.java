package ru.olegcherednik.zip4jvm.model.builders;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.aes.AesStrength;
import ru.olegcherednik.zip4jvm.model.AesExtraFieldRecord;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

/**
 * @author Oleg Cherednik
 * @since 30.08.2019
 */
@RequiredArgsConstructor
final class AesExtraDataRecordBuilder {

    private final ZipEntry entry;

    public AesExtraFieldRecord build() {
        AesStrength strength = entry.getStrength();

        if (strength == AesStrength.NULL)
            return AesExtraFieldRecord.NULL;

        return AesExtraFieldRecord.builder()
                                  .dataSize(7)
                                  .vendor("AE")
                                  .versionNumber(2)
                                  .strength(strength)
                                  .compressionMethod(entry.getCompressionMethod()).build();
    }

}
