package ru.olegcherednik.zip4jvm.io.in.entry;

import org.apache.commons.io.IOUtils;
import ru.olegcherednik.zip4jvm.crypto.Decoder;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.in.data.DecoderDataInput;
import ru.olegcherednik.zip4jvm.io.in.data.DecoderDataInputDecorator;
import ru.olegcherednik.zip4jvm.io.readers.LocalFileHeaderReader;
import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.model.LocalFileHeader;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.function.Function;

/**
 * This stream is responsible to read {@link ZipEntry} data. It could be encrypted; therefore all read data should be go throw given {@link Decoder}.
 *
 * @author Oleg Cherednik
 * @since 04.08.2019
 */
public abstract class EntryInputStream extends EntryMetadataInputStream {

    public static EntryInputStream create(ZipEntry zipEntry, Function<Charset, Charset> charsetCustomizer, DataInput in) throws IOException {
        LocalFileHeader localFileHeader = new LocalFileHeaderReader(zipEntry.getLocalFileHeaderOffs(), charsetCustomizer).read(in);
        // TODO check why do I use Supplier here
        zipEntry.setDataDescriptorAvailable(() -> localFileHeader.getGeneralPurposeFlag().isDataDescriptorAvailable());
        // TODO check that localFileHeader matches fileHeader
        CompressionMethod compressionMethod = zipEntry.getCompressionMethod();

        if (compressionMethod == CompressionMethod.STORE)
            return new StoreEntryInputStream(zipEntry, in);
        if (compressionMethod == CompressionMethod.DEFLATE)
            return new InflateEntryInputStream(zipEntry, in);
        if (compressionMethod == CompressionMethod.LZMA)
            return new LzmaEntryInputStream(zipEntry, in);

        throw new Zip4jvmException("Compression is not supported: " + compressionMethod);
    }

    protected final DecoderDataInput in;
    private final long compressedSize;

    private final byte[] buf = new byte[1];

    protected EntryInputStream(ZipEntry zipEntry, DataInput in) throws IOException {
        super(zipEntry, in);
        this.in = new DecoderDataInputDecorator(in, zipEntry.createDecoder(in));
        compressedSize = this.in.getDataCompressedSize(zipEntry.getCompressedSize());
    }

    protected long getAvailableCompressedBytes() {
        return compressedSize - readCompressedBytes;
    }

    @Override
    public final int read() throws IOException {
        int len = read(buf, 0, 1);
        return len == IOUtils.EOF ? IOUtils.EOF : buf[0] & 0xFF;
    }

    @Override
    public void close() throws IOException {
        in.decodingAccomplished();
        super.close();
    }

}
