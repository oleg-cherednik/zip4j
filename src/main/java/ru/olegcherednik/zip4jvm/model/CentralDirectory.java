package ru.olegcherednik.zip4jvm.model;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang.ArrayUtils;

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

    private List<FileHeader> fileHeaders = Collections.emptyList();
    private DigitalSignature digitalSignature;

    /** see 4.3.12 */
    @Getter
    @Setter
    public static class FileHeader {

        public static final int SIGNATURE = 0x02014B50;

        // size:4 - signature (0x02014b50)
        // size:2 - version made by
        private Version versionMadeBy = Version.NULL;
        // size:2 - version needed to extractEntries
        private Version versionToExtract = Version.NULL;
        // size:2 - general purpose bit flag
        private GeneralPurposeFlag generalPurposeFlag = new GeneralPurposeFlag();
        // size:2 - compression method
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
        private final InternalFileAttributes internalFileAttributes = new InternalFileAttributes();
        // size:4 - external file attributes
        private ExternalFileAttributes externalFileAttributes = ExternalFileAttributes.NULL;
        // size:4 - relative offset of local header
        private long localFileHeaderOffs;
        // size:n - file name
        private String fileName;
        // size:m - extra field
        private ExtraField extraField = ExtraField.NULL;
        // size:k - comment
        private String comment;

        public byte[] getFileName(Charset charset) {
            return fileName == null ? ArrayUtils.EMPTY_BYTE_ARRAY : fileName.getBytes(charset);
        }

        public byte[] getComment(Charset charset) {
            return comment == null ? ArrayUtils.EMPTY_BYTE_ARRAY : comment.getBytes(charset);
        }

        public CompressionMethod getOriginalCompressionMethod() {
            return compressionMethod == CompressionMethod.AES ? extraField.getAesExtraDataRecord().getCompressionMethod() : compressionMethod;
        }

        public boolean isZip64() {
            return extraField.getExtendedInfo() != Zip64.ExtendedInfo.NULL;
        }

        public void setInternalFileAttributes(InternalFileAttributes internalFileAttributes) {
            this.internalFileAttributes.readFrom(internalFileAttributes);
        }

        public void setExtraField(ExtraField extraField) {
            this.extraField = ExtraField.builder().addRecord(extraField).build();
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
            return localFileHeaderOffs > Zip64.LIMIT_DWORD;
        }

        @Override
        public String toString() {
            return fileName;
        }

    }

    /** see 4.3.13 */
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
