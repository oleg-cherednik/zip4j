package ru.olegcherednik.zip4jvm.model.entry;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import ru.olegcherednik.zip4jvm.ZipFile;
import ru.olegcherednik.zip4jvm.crypto.Decoder;
import ru.olegcherednik.zip4jvm.crypto.Encoder;
import ru.olegcherednik.zip4jvm.crypto.aes.AesEngine;
import ru.olegcherednik.zip4jvm.crypto.aes.AesStrength;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.CompressionLevel;
import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.model.Encryption;
import ru.olegcherednik.zip4jvm.model.ExternalFileAttributes;
import ru.olegcherednik.zip4jvm.model.InternalFileAttributes;
import ru.olegcherednik.zip4jvm.model.LocalFileHeader;
import ru.olegcherednik.zip4jvm.utils.function.ZipEntryInputStreamSupplier;

import java.io.IOException;
import java.io.InputStream;
import java.util.Comparator;
import java.util.function.BooleanSupplier;

/**
 * Represents one single entry in zip archive, i.e. one instance of {@link LocalFileHeader} and related {@link
 * ru.olegcherednik.zip4jvm.model.CentralDirectory.FileHeader}.
 *
 * @author Oleg Cherednik
 * @since 26.07.2019
 */
@Getter
@Setter
@RequiredArgsConstructor
@SuppressWarnings("UnnecessaryFullyQualifiedName")
public abstract class ZipEntry {

    public static final Comparator<ZipEntry> SORT_BY_DISC_LOCAL_FILE_HEADER_OFFS =
            Comparator.comparingLong(ZipEntry::getDisk).thenComparing(ZipEntry::getLocalFileHeaderOffs);

    private final String fileName;
    private final int lastModifiedTime;
    private final ExternalFileAttributes externalFileAttributes;

    protected final CompressionMethod compressionMethod;
    private final CompressionLevel compressionLevel;
    protected final Encryption encryption;
    @Getter(AccessLevel.NONE)
    private final ZipEntryInputStreamSupplier inputStreamSup;

    /**
     * {@literal true} only if section {@link ru.olegcherednik.zip4jvm.model.Zip64.ExtendedInfo} exists in {@link LocalFileHeader} and
     * {@link ru.olegcherednik.zip4jvm.model.CentralDirectory.FileHeader}. In other words, do set this to {@code true}, to write given entry in
     * ZIP64 format.
     */
    private boolean zip64;

    private char[] password;
    private long disk;
    private long localFileHeaderOffs;
    @Getter(AccessLevel.NONE)
    private BooleanSupplier dataDescriptorAvailable = () -> false;
    private long uncompressedSize;
    private long compressedSize;
    private boolean lzmaEosMarker = true;

    private String comment;
    private boolean utf8;

    public boolean isRegularFile() {
        return false;
    }

    public boolean isDirectory() {
        return false;
    }

    public final AesStrength getStrength() {
        return AesEngine.getStrength(encryption);
    }

    public final boolean isEncrypted() {
        return encryption != Encryption.OFF;
    }

    public InputStream getInputStream() throws IOException {
        return inputStreamSup.get(this);
    }

    public CompressionMethod getCompressionMethodForBuilder() {
        return encryption.isAes() ? CompressionMethod.AES : compressionMethod;
    }

    @Override
    public String toString() {
        return fileName;
    }

    public InternalFileAttributes getInternalFileAttributes() throws IOException {
        return new InternalFileAttributes();
    }

    public long getChecksum() {
        return 0;
    }

    public void setChecksum(long checksum) {
        /* nothing to set */
    }

    public final boolean isDataDescriptorAvailable() {
        return dataDescriptorAvailable.getAsBoolean();
    }

    public final ZipFile.Entry createImmutableEntry() {
        ZipFile.Entry.Builder builder = ZipFile.Entry.builder()
                                                     .inputStreamSupplier(this::getInputStream)
                                                     .lastModifiedTime(lastModifiedTime)
                                                     .uncompressedSize(uncompressedSize)
                                                     .externalFileAttributes(externalFileAttributes);

        if (isRegularFile())
            builder.fileName(fileName);
        else
            builder.directoryName(fileName);

        return builder.build();
    }

    public Decoder createDecoder(DataInput in) throws IOException {
        return Decoder.NULL;
    }

    public Encoder createEncoder() {
        return Encoder.NULL;
    }

}
