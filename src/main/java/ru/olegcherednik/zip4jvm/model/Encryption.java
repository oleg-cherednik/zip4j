package ru.olegcherednik.zip4jvm.model;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.Decoder;
import ru.olegcherednik.zip4jvm.crypto.Encoder;
import ru.olegcherednik.zip4jvm.crypto.aes.AesDecoder;
import ru.olegcherednik.zip4jvm.crypto.aes.AesEncoder;
import ru.olegcherednik.zip4jvm.crypto.aes.AesEngine;
import ru.olegcherednik.zip4jvm.crypto.aes.AesExtraDataRecord;
import ru.olegcherednik.zip4jvm.crypto.pkware.PkwareDecoder;
import ru.olegcherednik.zip4jvm.crypto.pkware.PkwareEncoder;
import ru.olegcherednik.zip4jvm.crypto.strong.StrongDecoder;
import ru.olegcherednik.zip4jvm.crypto.strong.StrongEncoder;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 09.03.2019
 */
@Getter
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public enum Encryption {
    OFF(zipEntry -> Encoder.NULL, (zipEntry, in) -> Decoder.NULL, ZipEntry::getChecksum, Compression::getMethod, (extensibleDataSector, in) -> null),
    STRONG(StrongEncoder::create, StrongDecoder::create, ZipEntry::getChecksum, Compression::getMethod, (extensibleDataSector, in) -> null),
    PKWARE(PkwareEncoder::create, PkwareDecoder::create, ZipEntry::getChecksum, Compression::getMethod, (extensibleDataSector, in) -> null),
    AES_128(AesEncoder::create, AesDecoder::create, entry -> 0L, compression -> CompressionMethod.AES, (extensibleDataSector, in) -> null),
    AES_192(AES_128.createEncoder, AES_128.createDecoder, AES_128.checksum, AES_128.compressionMethod, (extensibleDataSector, in) -> null),
    AES_256(AES_128.createEncoder, AES_128.createDecoder, AES_128.checksum, AES_128.compressionMethod, AesDecoder::create);

    private final Function<ZipEntry, Encoder> createEncoder;
    private final CreateDecoder createDecoder;
    private final Function<ZipEntry, Long> checksum;
    private final Function<Compression, CompressionMethod> compressionMethod;
    private final CreateDecoderCentral createDecoderCentral;

    public static Encryption get(ExtraField extraField, GeneralPurposeFlag generalPurposeFlag) {
        if (!generalPurposeFlag.isEncrypted())
            return OFF;
        if (generalPurposeFlag.isStrongEncryption())
//            throw new Zip4jvmException("Strong encryption is not supported");
            return STRONG;
        if (extraField.getAesExtraDataRecord() != AesExtraDataRecord.NULL)
            return AesEngine.getEncryption(extraField.getAesExtraDataRecord().getStrength());
        return generalPurposeFlag.isStrongEncryption() ? STRONG : PKWARE;
    }

    public interface CreateDecoder {

        Decoder apply(ZipEntry zipEntry, DataInput in) throws IOException;

    }

    public interface CreateDecoderCentral {

        Decoder apply(Zip64.ExtensibleDataSector extensibleDataSector, DataInput in) throws IOException;

    }

}


