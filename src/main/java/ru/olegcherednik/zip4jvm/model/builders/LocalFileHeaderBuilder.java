package ru.olegcherednik.zip4jvm.model.builders;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.model.Encryption;
import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.model.GeneralPurposeFlag;
import ru.olegcherednik.zip4jvm.model.LocalFileHeader;
import ru.olegcherednik.zip4jvm.model.Version;
import ru.olegcherednik.zip4jvm.model.Zip64;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

/**
 * @author Oleg Cherednik
 * @since 27.08.2019
 */
@RequiredArgsConstructor
public final class LocalFileHeaderBuilder {

    public static final long LOOK_IN_DATA_DESCRIPTOR = 0;
    public static final long LOOK_IN_EXTRA_FIELD = Zip64.LIMIT_DWORD;

    private final ZipEntry zipEntry;

    public LocalFileHeader build() {
        LocalFileHeader localFileHeader = new LocalFileHeader();
        localFileHeader.setVersionToExtract(Version.of(Version.FileSystem.MS_DOS_OS2_NT_FAT, 20));
        localFileHeader.setGeneralPurposeFlag(createGeneralPurposeFlag());
        localFileHeader.setCompressionMethod(zipEntry.getCompressionMethodForBuilder());
        localFileHeader.setLastModifiedTime(zipEntry.getLastModifiedTime());
        localFileHeader.setCrc32(getCrc32());
        localFileHeader.setCompressedSize(getSize(zipEntry.getCompressedSize()));
        localFileHeader.setUncompressedSize(getSize(zipEntry.getUncompressedSize()));
        localFileHeader.setFileName(zipEntry.getFileName());
        localFileHeader.setExtraField(createExtraField());
        return localFileHeader;
    }

    private GeneralPurposeFlag createGeneralPurposeFlag() {
        GeneralPurposeFlag generalPurposeFlag = new GeneralPurposeFlag();
        generalPurposeFlag.setCompressionLevel(zipEntry.getCompressionLevel());
        generalPurposeFlag.setDataDescriptorAvailable(zipEntry.isDataDescriptorAvailable());
        generalPurposeFlag.setUtf8(zipEntry.isUtf8());
        generalPurposeFlag.setEncrypted(zipEntry.getEncryption() != Encryption.OFF);
//        generalPurposeFlag.setStrongEncryption(entry.getEncryption() == Encryption.STRONG);
        generalPurposeFlag.setStrongEncryption(false);
        generalPurposeFlag.setLzmaEosMarker(zipEntry.isLzmaEosMarker());

        return generalPurposeFlag;
    }

    private ExtraField createExtraField() {
        return ExtraField.builder()
                         .addRecord(createExtendedInfo())
                         .addRecord(new AesExtraDataRecordBuilder(zipEntry).build()).build();
    }

    private Zip64.ExtendedInfo createExtendedInfo() {
        if (zipEntry.isDataDescriptorAvailable())
            return Zip64.ExtendedInfo.NULL;
        if (zipEntry.isZip64())
            return Zip64.ExtendedInfo.builder()
                                     .compressedSize(zipEntry.getCompressedSize())
                                     .uncompressedSize(zipEntry.getUncompressedSize()).build();
        return Zip64.ExtendedInfo.NULL;
    }

    private long getCrc32() {
        if (zipEntry.isDataDescriptorAvailable())
            return LOOK_IN_DATA_DESCRIPTOR;
        return zipEntry.getEncryption().getChecksum().apply(zipEntry);
    }

    private long getSize(long size) {
        if (zipEntry.isDataDescriptorAvailable())
            return LOOK_IN_DATA_DESCRIPTOR;
        if (zipEntry.isZip64())
            return LOOK_IN_EXTRA_FIELD;
        return size;
    }

}
