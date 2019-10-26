package ru.olegcherednik.zip4jvm.io.writers;

import lombok.RequiredArgsConstructor;
import org.apache.commons.io.IOUtils;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.io.in.SingleZipInputStream;
import ru.olegcherednik.zip4jvm.io.in.SplitZipInputStream;
import ru.olegcherednik.zip4jvm.io.out.DataOutput;
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
import java.nio.charset.Charset;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 12.09.2019
 */
@RequiredArgsConstructor
public class ExistedEntryWriter implements Writer {

    private static final String LOCAL_FILE_HEADER_OFFS = "localFileHeaderOffs";

    private final ZipModel srcZipModel;
    private final String entryName;
    private final ZipModel destZipModel;
    private final char[] password;

    @Override
    public void write(DataOutput out) throws IOException {
        ZipEntry entry = srcZipModel.getEntryByFileName(entryName);
        entry.setPassword(entry.isEncrypted() ? password : null);

        try (CopyEntryInputStream in = new CopyEntryInputStream(entry, srcZipModel)) {
            if (!destZipModel.hasEntry(entryName))
                destZipModel.addEntry(entry);

            out.mark(LOCAL_FILE_HEADER_OFFS);

            in.copyLocalFileHeader(out);
            in.copyEncryptionHeaderAndData(out);
            in.copyDataDescriptor(out);

            entry.setLocalFileHeaderOffs(out.getMark(LOCAL_FILE_HEADER_OFFS));
        }
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
            in = zipModel.isSplit() ? new SplitZipInputStream(zipModel, zipEntry.getDisk()) : new SingleZipInputStream(zipModel.getFile());
        }

        public void copyLocalFileHeader(DataOutput out) throws IOException {
            Function<Charset, Charset> charsetCustomizer = Charsets.STANDARD_ZIP_CHARSET;
            LocalFileHeader localFileHeader = new LocalFileHeaderReader(zipEntry.getLocalFileHeaderOffs(), charsetCustomizer).read(in);
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
