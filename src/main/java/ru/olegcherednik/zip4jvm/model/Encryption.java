package ru.olegcherednik.zip4jvm.model;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.Decoder;
import ru.olegcherednik.zip4jvm.crypto.Encoder;
import ru.olegcherednik.zip4jvm.crypto.aes.AesDecoder;
import ru.olegcherednik.zip4jvm.crypto.aes.AesEncoder;
import ru.olegcherednik.zip4jvm.crypto.aes.AesEngine;
import ru.olegcherednik.zip4jvm.crypto.pkware.PkwareDecoder;
import ru.olegcherednik.zip4jvm.crypto.pkware.PkwareEncoder;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.entry.RegularFileZipEntry;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 09.03.2019
 */
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public enum Encryption {
    OFF(zipEntry -> Encoder.NULL, (zipEntry, in) -> Decoder.NULL, ZipEntry::getChecksum),
    PKWARE(PkwareEncoder::create, PkwareDecoder::create, ZipEntry::getChecksum),
    AES_128(AesEncoder::create, AesDecoder::create, entry -> 0L),
    AES_192(AES_128.createEncoder, AES_128.createDecoder, AES_128.checksum),
    AES_256(AES_128.createEncoder, AES_128.createDecoder, AES_128.checksum);

    @Getter
    private final Function<ZipEntry, Encoder> createEncoder;
    private final CreateDecoder createDecoder;
    @Getter
    private final Function<ZipEntry, Long> checksum;

    public boolean isAes() {
        return this == AES_128 || this == AES_192 || this == AES_256;
    }

    public Decoder createDecoder(RegularFileZipEntry zipEntry, DataInput in) throws IOException {
        return createDecoder.apply(zipEntry, in);
    }

    public Encoder createEncoder(RegularFileZipEntry zipEntry) {
        return createEncoder.apply(zipEntry);
    }

    public static Encryption get(ExtraField extraField, GeneralPurposeFlag generalPurposeFlag) {
        if (generalPurposeFlag.isStrongEncryption())
            throw new Zip4jvmException("Strong encryption is not supported");
        if (!generalPurposeFlag.isEncrypted())
            return OFF;
        if (extraField.getAesExtraDataRecord() != AesExtraFieldRecord.NULL)
            return AesEngine.getEncryption(extraField.getAesExtraDataRecord().getStrength());
        return PKWARE;
    }

    public interface CreateDecoder {

        Decoder apply(ZipEntry zipEntry, DataInput in) throws IOException;
    }

}


