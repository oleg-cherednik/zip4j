package ru.olegcherednik.zip4jvm.io.writers;

import lombok.RequiredArgsConstructor;
import org.apache.commons.io.IOUtils;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.io.readers.DataDescriptorReader;
import ru.olegcherednik.zip4jvm.io.readers.LocalFileHeaderReader;
import ru.olegcherednik.zip4jvm.model.Charsets;
import ru.olegcherednik.zip4jvm.model.DataDescriptor;
import ru.olegcherednik.zip4jvm.model.LocalFileHeader;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;
import ru.olegcherednik.zip4jvm.utils.ZipUtils;
import ru.olegcherednik.zip4jvm.utils.function.Writer;

import java.io.Closeable;
import java.io.IOException;

/**
 * This writer copy existed {@link ZipEntry} block from one zip file to another as is. This block is not modified during the copy.
 *
 * @author Oleg Cherednik
 * @since 12.09.2019
 */
@RequiredArgsConstructor
public class ExistedEntryWriter implements Writer {

    private final ZipModel srcZipModel;
    private final String entryName;
    private final ZipModel destZipModel;
    private final char[] password;

    @Override
    public void write(DataOutput out) throws IOException {
        ZipEntry entry = srcZipModel.getZipEntryByFileName(entryName);
        // TODO it seems that this should not be done, because we just copy encrypted/not encrypted entry
        entry.setPassword(entry.isEncrypted() ? password : null);

        long offs = out.getOffs();
        long disk = out.getDisk();

        try (CopyEntryInputStream in = new CopyEntryInputStream(entry, srcZipModel)) {
            if (!destZipModel.hasEntry(entryName))
                destZipModel.addEntry(entry);

            in.copyLocalFileHeader(out);
            in.copyEncryptionHeaderAndData(out);
            in.copyDataDescriptor(out);
            // TODO probably should set compressed size here
        }

        entry.setLocalFileHeaderOffs(offs);
        entry.setDisk(disk);
    }

    @Override
    public String toString() {
        return "->" + entryName;
    }

    private static final class CopyEntryInputStream implements Closeable {

        private final ZipEntry zipEntry;
        private final DataInput in;

        public CopyEntryInputStream(ZipEntry zipEntry, ZipModel zipModel) throws IOException {
            this.zipEntry = zipEntry;
            in = zipModel.createDataInput(zipEntry.getFileName());
        }

        public void copyLocalFileHeader(DataOutput out) throws IOException {
            LocalFileHeader localFileHeader = new LocalFileHeaderReader(zipEntry.getLocalFileHeaderOffs(), Charsets.UNMODIFIED).read(in);
            zipEntry.setDataDescriptorAvailable(() -> localFileHeader.getGeneralPurposeFlag().isDataDescriptorAvailable());
            new LocalFileHeaderWriter(localFileHeader).write(out);
        }

        public void copyEncryptionHeaderAndData(DataOutput out) throws IOException {
            long size = zipEntry.getCompressedSize();
            byte[] buf = new byte[1024 * 4];

            while (size > 0) {
                int n = in.read(buf, 0, (int)Math.min(buf.length, size));

                if (n == IOUtils.EOF)
                    throw new Zip4jvmException("Unexpected end of file");

                out.write(buf, 0, n);
                size -= n;
            }
        }

        public void copyDataDescriptor(DataOutput out) throws IOException {
            if (zipEntry.isDataDescriptorAvailable()) {
                DataDescriptor dataDescriptor = DataDescriptorReader.get(zipEntry.isZip64()).read(in);
                DataDescriptorWriter.get(zipEntry.isZip64(), dataDescriptor).write(out);
            }
        }

        @Override
        public void close() throws IOException {
            in.close();
        }

        @Override
        public String toString() {
            return ZipUtils.toString(in.getOffs());
        }

    }
}
