package ru.olegcherednik.zip4jvm.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import org.apache.commons.lang.ArrayUtils;
import ru.olegcherednik.zip4jvm.utils.ZipUtils;

import java.nio.charset.Charset;
import java.util.Collections;
import java.util.List;

/**
 * see 4.3.12
 *
 * @author Oleg Cherednik
 * @since 05.03.2019
 */
@Getter
@Setter
public class CentralDirectory {

    @NonNull
    private List<FileHeader> fileHeaders = Collections.emptyList();
    private DigitalSignature digitalSignature;

    /** see 4.3.12 */
    @Getter
    @Setter
    @NoArgsConstructor
    public static class FileHeader {

        public static final int SIGNATURE = 0x02014B50;
        public static final int VERSION = 20;

        // size:4 - signature (0x02014b50)
        // size:2 - version made by
        private int versionMadeBy = VERSION;
        // size:2 - version needed to extractEntries
        private int versionToExtract = VERSION;
        // size:2 - general purpose bit flag
        @NonNull
        private GeneralPurposeFlag generalPurposeFlag = new GeneralPurposeFlag();
        // size:2 - compression method
        @NonNull
        private CompressionMethod compressionMethod = CompressionMethod.STORE;
        // size:2 - last mod file time
        // size:2 - last mod file date
        private int lastModifiedTime;
        // size:4 - checksum
        private long crc32;
        // size:4 - compressed size
        private long compressedSize;
        // size:4 - uncompressed size
        private long uncompressedSize;
        // size:2 - file name length (n)
        // size:2 - extra field length (m)
        // size:2 - comment length (k)
        private int commentLength;
        // size:2 - disk number start
        private int disk;
        // size:2 - internal file attributes
        @NonNull
        private InternalFileAttributes internalFileAttributes = InternalFileAttributes.NULL;
        // size:4 - external file attributes
        @NonNull
        private ExternalFileAttributes externalFileAttributes = ExternalFileAttributes.NULL;
        // size:4 - relative offset of local header
        private long offsLocalFileHeader;
        // size:n - file name
        private String fileName;
        // size:m - extra field
        @NonNull
        private ExtraField extraField = new ExtraField();
        // size:k - comment
        private String comment;

        public FileHeader(String fileName) {
            this.fileName = fileName;
        }

        @NonNull
        public byte[] getFileName(@NonNull Charset charset) {
            return fileName != null ? fileName.getBytes(charset) : ArrayUtils.EMPTY_BYTE_ARRAY;
        }

        @NonNull
        public byte[] getComment(@NonNull Charset charset) {
            return comment != null ? comment.getBytes(charset) : ArrayUtils.EMPTY_BYTE_ARRAY;
        }

        @NonNull
        public Compression getCompression() {
            if (compressionMethod == CompressionMethod.AES)
                return Compression.parseCompressionMethod(extraField.getAesExtraDataRecord().getCompressionMethod());
            return Compression.parseCompressionMethod(compressionMethod);
        }

        public boolean isDirectory() {
            return ZipUtils.isDirectory(fileName);
        }

        public boolean isZip64() {
            return extraField.getExtendedInfo() != Zip64.ExtendedInfo.NULL;
        }

        public void setExtraField(@NonNull ExtraField extraField) {
            this.extraField.setFrom(extraField);
            generalPurposeFlag.setEncrypted(isEncrypted());
        }

        public void setGeneralPurposeFlagData(int data) {
            generalPurposeFlag.read(data);
            generalPurposeFlag.setEncrypted(isEncrypted());
        }

        public boolean isEncrypted() {
            return getEncryption() != Encryption.OFF;
        }

        public Encryption getEncryption() {
            return Encryption.get(extraField, generalPurposeFlag);
        }

        public boolean isWriteZip64OffsetLocalHeader() {
            return offsLocalFileHeader > Zip64.LIMIT;
        }

        @Override
        public String toString() {
            return fileName;
        }

    }

    @Getter
    @Setter
    public static class DigitalSignature {

        public static final int SIGNATURE = 0x05054B50;

        // size:4 - header signature (0x06054b50)
        // size:2 - size of data (n)
        // size:n - signature data
        private byte[] signatureData;

    }

}