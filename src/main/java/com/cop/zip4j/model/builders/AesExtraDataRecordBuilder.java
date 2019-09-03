package com.cop.zip4j.model.builders;

import com.cop.zip4j.crypto.aes.AesStrength;
import com.cop.zip4j.model.AesExtraDataRecord;
import com.cop.zip4j.model.entry.PathZipEntry;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * @author Oleg Cherednik
 * @since 30.08.2019
 */
@RequiredArgsConstructor
final class AesExtraDataRecordBuilder {

    @NonNull
    private final PathZipEntry entry;

    @NonNull
    public AesExtraDataRecord create() {
        AesStrength strength = entry.getStrength();

        if (strength == AesStrength.NULL)
            return AesExtraDataRecord.NULL;

        return AesExtraDataRecord.builder()
                                 .size(7)
                                 .vendor("AE")
                                 .versionNumber((short)2)
                                 .strength(strength)
                                 .compressionMethod(entry.getCompression().getMethod())
                                 .build();
    }

}
