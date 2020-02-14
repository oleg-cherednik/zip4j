package ru.olegcherednik.zip4jvm.model.entry;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.ZipFile;
import ru.olegcherednik.zip4jvm.io.in.entry.EntryInputStream;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.model.CompressionLevel;
import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.model.Encryption;
import ru.olegcherednik.zip4jvm.model.ExternalFileAttributes;
import ru.olegcherednik.zip4jvm.model.GeneralPurposeFlag;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.model.settings.ZipEntrySettings;
import ru.olegcherednik.zip4jvm.utils.ZipUtils;
import ru.olegcherednik.zip4jvm.utils.function.ZipEntryInputStreamSupplier;
import ru.olegcherednik.zip4jvm.utils.time.DosTimestampConverter;

import java.nio.charset.Charset;
import java.util.function.Function;

import static ru.olegcherednik.zip4jvm.model.ZipModel.MAX_ENTRY_SIZE;
import static ru.olegcherednik.zip4jvm.model.ZipModel.MAX_LOCAL_FILE_HEADER_OFFS;
import static ru.olegcherednik.zip4jvm.model.ZipModel.MAX_TOTAL_DISKS;

/**
 * @author Oleg Cherednik
 * @since 04.09.2019
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ZipEntryBuilder {

    public static ZipEntry build(ZipFile.Entry entry, ZipEntrySettings entrySettings) {
        return new EntryBased(entry, entrySettings).build();
    }

    public static ZipEntry build(CentralDirectory.FileHeader fileHeader, ZipModel zipModel, Function<Charset, Charset> charsetCustomizer) {
        return new FileHeaderBased(fileHeader, zipModel, charsetCustomizer).build();
    }

    @RequiredArgsConstructor
    private static final class EntryBased {

        private final ZipFile.Entry entry;
        private final ZipEntrySettings entrySettings;

        public ZipEntry build() {
            boolean regularFile = entry.isRegularFile();
            ZipEntry zipEntry = regularFile ? createRegularFileEntry() : createDirectoryEntry();
            zipEntry.setComment(entrySettings.getComment());
            zipEntry.setUtf8(entrySettings.isUtf8());
            return zipEntry;
        }

        private ZipEntry createDirectoryEntry() {
            String fileName = ZipUtils.getFileName(entry);
            int lastModifiedTime = DosTimestampConverter.javaToDosTime(entry.getLastModifiedTime());
            ExternalFileAttributes externalFileAttributes = entry.getExternalFileAttributes();
            return new DirectoryZipEntry(fileName, lastModifiedTime, externalFileAttributes);
        }

        private ZipEntry createRegularFileEntry() {
            String fileName = ZipUtils.getFileName(entry);
            int lastModifiedTime = DosTimestampConverter.javaToDosTime(entry.getLastModifiedTime());
            ExternalFileAttributes externalFileAttributes = entry.getExternalFileAttributes();

            CompressionMethod compressionMethod = entry.getUncompressedSize() == 0 ? CompressionMethod.STORE
                                                                                   : entrySettings.getCompression().getMethod();
            CompressionLevel compressionLevel = entrySettings.getCompressionLevel();
            Encryption encryption = entrySettings.getEncryption();
            ZipEntryInputStreamSupplier inputStreamSup = zipEntry -> entry.getInputStream();

            RegularFileZipEntry zipEntry = new RegularFileZipEntry(fileName, lastModifiedTime, externalFileAttributes, compressionMethod,
                    compressionLevel, encryption, inputStreamSup);

            zipEntry.setDataDescriptorAvailable(() -> true);
            zipEntry.setZip64(entrySettings.isZip64());
            zipEntry.setPassword(entrySettings.getPassword());
            zipEntry.setComment(entrySettings.getComment());
            zipEntry.setUtf8(entrySettings.isUtf8());

            return zipEntry;
        }
    }

    @RequiredArgsConstructor
    private static final class FileHeaderBased {

        private final CentralDirectory.FileHeader fileHeader;
        private final ZipModel zipModel;
        private final Function<Charset, Charset> charsetCustomizer;

        public ZipEntry build() {
            boolean regularFile = ZipUtils.isRegularFile(fileHeader.getFileName());
            ZipEntry zipEntry = regularFile ? createRegularFileEntry() : createDirectoryEntry();
            zipEntry.setChecksum(fileHeader.getCrc32());
            zipEntry.setUncompressedSize(getUncompressedSize());
            zipEntry.setCompressedSize(getCompressedSize());
            zipEntry.setDisk(getDisk());
            zipEntry.setLocalFileHeaderOffs(getLocalFileHeaderOffs());
            return zipEntry;
        }

        private ZipEntry createRegularFileEntry() {
            String fileName = ZipUtils.normalizeFileName(fileHeader.getFileName());
            int lastModifiedTime = fileHeader.getLastModifiedTime();
            GeneralPurposeFlag generalPurposeFlag = fileHeader.getGeneralPurposeFlag();

            CompressionMethod compressionMethod = fileHeader.getOriginalCompressionMethod();
            CompressionLevel compressionLevel = generalPurposeFlag.getCompressionLevel();
            Encryption encryption = fileHeader.getEncryption();
            ExternalFileAttributes externalFileAttributes = fileHeader.getExternalFileAttributes();

            ZipEntryInputStreamSupplier inputStreamSup = createInputStreamSupplier();

            RegularFileZipEntry zipEntry = new RegularFileZipEntry(fileName, lastModifiedTime, externalFileAttributes, compressionMethod,
                    compressionLevel, encryption, inputStreamSup);

            zipEntry.setDataDescriptorAvailable(generalPurposeFlag::isDataDescriptorAvailable);
            zipEntry.setLzmaEosMarker(generalPurposeFlag.isLzmaEosMarker());
            zipEntry.setZip64(fileHeader.isZip64());
            zipEntry.setComment(fileHeader.getComment());
            zipEntry.setUtf8(fileHeader.getGeneralPurposeFlag().isUtf8());

            return zipEntry;
        }

        private ZipEntry createDirectoryEntry() {
            String fileName = ZipUtils.normalizeFileName(fileHeader.getFileName());
            int lastModifiedTime = fileHeader.getLastModifiedTime();
            ExternalFileAttributes externalFileAttributes = fileHeader.getExternalFileAttributes();
            return new DirectoryZipEntry(fileName, lastModifiedTime, externalFileAttributes);
        }

        private ZipEntryInputStreamSupplier createInputStreamSupplier() {
            return zipEntry -> EntryInputStream.create(zipEntry, charsetCustomizer, zipModel.createDataInput(zipEntry.getFileName()));
        }

        private long getDisk() {
            if (fileHeader.getDisk() == MAX_TOTAL_DISKS)
                return fileHeader.getExtraField().getExtendedInfo().getDisk();
            return fileHeader.getDisk();
        }

        private long getCompressedSize() {
            if (fileHeader.getCompressedSize() == MAX_ENTRY_SIZE)
                return fileHeader.getExtraField().getExtendedInfo().getCompressedSize();
            return fileHeader.getCompressedSize();
        }

        private long getUncompressedSize() {
            if (fileHeader.getUncompressedSize() == MAX_ENTRY_SIZE)
                return fileHeader.getExtraField().getExtendedInfo().getUncompressedSize();
            return fileHeader.getUncompressedSize();
        }

        private long getLocalFileHeaderOffs() {
            if (fileHeader.getLocalFileHeaderOffs() == MAX_LOCAL_FILE_HEADER_OFFS)
                return fileHeader.getExtraField().getExtendedInfo().getLocalFileHeaderOffs();
            return fileHeader.getLocalFileHeaderOffs();
        }

    }
}
