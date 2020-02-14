package ru.olegcherednik.zip4jvm.io.in.entry;

import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.readers.DataDescriptorReader;
import ru.olegcherednik.zip4jvm.model.DataDescriptor;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

/**
 * This stream reads all {@link ZipEntry} related metadata like {@link DataDescriptor}. These data are not encrypted; therefore this stream cannot
 * be used to read {@link ZipEntry} payload (that could be encrypted).
 *
 * @author Oleg Cherednik
 * @since 08.02.2020
 */
abstract class EntryMetadataInputStream extends InputStream {

    private final DataInput in;

    protected final ZipEntry zipEntry;
    protected final long uncompressedSize;

    private final Checksum checksum = new CRC32();

    protected long readCompressedBytes;
    protected long writtenUncompressedBytes;

    protected EntryMetadataInputStream(ZipEntry zipEntry, DataInput in) {
        this.zipEntry = zipEntry;
        this.in = in;
        uncompressedSize = Math.max(0, zipEntry.getUncompressedSize());
    }

    protected final void updateChecksum(byte[] buf, int offs, int len) {
        checksum.update(buf, offs, len);
    }

    @Override
    public int available() {
        return (int)Math.max(0, uncompressedSize - writtenUncompressedBytes);
    }

    @Override
    public final long skip(long n) throws IOException {
        return super.skip(n);
    }

    @Override
    public void close() throws IOException {
        readDataDescriptor();
        checkChecksum();
        checkUncompressedSize();
        in.close();
    }

    /** Just read {@link DataDescriptor} and ignore it's value. We got it from {@link ru.olegcherednik.zip4jvm.model.CentralDirectory.FileHeader} */
    @SuppressWarnings("UnnecessaryFullyQualifiedName")
    private void readDataDescriptor() throws IOException {
        if (zipEntry.isDataDescriptorAvailable())
            DataDescriptorReader.get(zipEntry.isZip64()).read(in);
    }

    private void checkChecksum() {
        long expected = zipEntry.getChecksum();
        long actual = checksum.getValue();

        if (expected > 0 && expected != actual)
            throw new Zip4jvmException("Checksum is not matched: " + zipEntry.getFileName());
    }

    private void checkUncompressedSize() {
        if (uncompressedSize != writtenUncompressedBytes)
            throw new Zip4jvmException("UncompressedSize is not matched: " + zipEntry.getFileName());
    }

    @Override
    public String toString() {
        return in.toString();
    }

}
