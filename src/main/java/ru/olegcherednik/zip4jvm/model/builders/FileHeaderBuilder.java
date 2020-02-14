package ru.olegcherednik.zip4jvm.model.builders;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.model.Encryption;
import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.model.GeneralPurposeFlag;
import ru.olegcherednik.zip4jvm.model.Version;
import ru.olegcherednik.zip4jvm.model.Zip64;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;

import static ru.olegcherednik.zip4jvm.model.ZipModel.MAX_LOCAL_FILE_HEADER_OFFS;
import static ru.olegcherednik.zip4jvm.model.ZipModel.MAX_TOTAL_DISKS;
import static ru.olegcherednik.zip4jvm.model.builders.LocalFileHeaderBuilder.LOOK_IN_EXTRA_FIELD;

/**
 * @author Oleg Cherednik
 * @since 30.08.2019
 */
@RequiredArgsConstructor
final class FileHeaderBuilder {

    private final ZipEntry zipEntry;

    public CentralDirectory.FileHeader build() throws IOException {
        CentralDirectory.FileHeader fileHeader = new CentralDirectory.FileHeader();

        fileHeader.setVersionMadeBy(Version.of(Version.FileSystem.MS_DOS_OS2_NT_FAT, 20));
        fileHeader.setVersionToExtract(Version.of(Version.FileSystem.MS_DOS_OS2_NT_FAT, 20));
        fileHeader.setGeneralPurposeFlag(createGeneralPurposeFlag());
        fileHeader.setCompressionMethod(zipEntry.getCompressionMethodForBuilder());
        fileHeader.setLastModifiedTime(zipEntry.getLastModifiedTime());
        fileHeader.setCrc32(zipEntry.getEncryption().getChecksum().apply(zipEntry));
        fileHeader.setCompressedSize(getSize(zipEntry.getCompressedSize()));
        fileHeader.setUncompressedSize(getSize(zipEntry.getUncompressedSize()));
        fileHeader.setCommentLength(0);
        fileHeader.setDisk(getDisk());
        fileHeader.setInternalFileAttributes(zipEntry.getInternalFileAttributes());
        fileHeader.setExternalFileAttributes(zipEntry.getExternalFileAttributes());
        fileHeader.setLocalFileHeaderOffs(getOffsLocalFileHeader());
        fileHeader.setFileName(zipEntry.getFileName());
        fileHeader.setExtraField(createExtraField());
        fileHeader.setComment(zipEntry.getComment());

        return fileHeader;
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
        if (zipEntry.isZip64())
            return Zip64.ExtendedInfo.builder()
                                     .compressedSize(zipEntry.getCompressedSize())
                                     .uncompressedSize(zipEntry.getUncompressedSize())
                                     .disk(zipEntry.getDisk())
                                     .localFileHeaderOffs(zipEntry.getLocalFileHeaderOffs()).build();
        return Zip64.ExtendedInfo.NULL;
    }

    private long getSize(long size) {
        return zipEntry.isZip64() ? LOOK_IN_EXTRA_FIELD : size;
    }

    private int getDisk() {
        return zipEntry.isZip64() ? MAX_TOTAL_DISKS : (int)zipEntry.getDisk();
    }

    private long getOffsLocalFileHeader() {
        return zipEntry.isZip64() ? MAX_LOCAL_FILE_HEADER_OFFS : zipEntry.getLocalFileHeaderOffs();
    }

}
