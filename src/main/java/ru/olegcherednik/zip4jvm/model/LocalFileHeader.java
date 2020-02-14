package ru.olegcherednik.zip4jvm.model;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang.ArrayUtils;

import java.nio.charset.Charset;

/**
 * see 4.3.7
 *
 * @author Oleg Cherednik
 * @since 12.03.2019
 */
@Getter
@Setter
public class LocalFileHeader {

    public static final int SIGNATURE = 0x04034B50;

    // size:4 - signature (0x04034B50)
    // size:2 - version needed to extractEntries
    private Version versionToExtract = Version.NULL;
    // size:2 - general purpose bit flag
    private GeneralPurposeFlag generalPurposeFlag = new GeneralPurposeFlag();
    // size:2 - compression method
    private CompressionMethod compressionMethod = CompressionMethod.STORE;
    // size:2 - last mod file time
    // size:2 - ast mod file date
    private int lastModifiedTime;
    // size:4 - crc-32
    private long crc32;
    // size:4 - compressed size
    private long compressedSize;
    // size:4 - uncompressed size
    private long uncompressedSize;
    // size:2 - file name length (n)
    // size:2 - extra field length (m)
    // size:n - file name
    private String fileName;
    // size:m - extra field
    private ExtraField extraField = ExtraField.NULL;

    public byte[] getFileName(Charset charset) {
        return fileName == null ? ArrayUtils.EMPTY_BYTE_ARRAY : fileName.getBytes(charset);
    }

    public CompressionMethod getOriginalCompressionMethod() {
        return compressionMethod == CompressionMethod.AES ? extraField.getAesExtraDataRecord().getCompressionMethod() : compressionMethod;
    }

    @Override
    public String toString() {
        return fileName;
    }

}
