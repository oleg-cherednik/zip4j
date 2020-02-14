package ru.olegcherednik.zip4jvm.io.out.entry;

import ru.olegcherednik.zip4jvm.io.lzma.LzmaInputStream;
import ru.olegcherednik.zip4jvm.io.lzma.LzmaOutputStream;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 09.02.2020
 */
final class LzmaEntryOutputStream extends EntryOutputStream {

    private final LzmaOutputStream lzma;
    private boolean writeHeader = true;

    public LzmaEntryOutputStream(ZipEntry zipEntry, DataOutput out) throws IOException {
        super(zipEntry, out);
        lzma = createEncoder();
    }

    private LzmaOutputStream createEncoder() throws IOException {
        long size = zipEntry.isLzmaEosMarker() ? -1 : zipEntry.getUncompressedSize();
        int compressionLevel = zipEntry.getCompressionLevel().getCode();
        return new LzmaOutputStream(out, new LzmaInputStream.Properties(compressionLevel), size);
    }

    @Override
    public void write(byte[] buf, int offs, int len) throws IOException {
        super.write(buf, offs, len);

        if (writeHeader) {
            out.writeByte((byte)19);    // major version
            out.writeByte((byte)0);     // minor version
            out.writeWord(5);           // header size
            lzma.writeHeader();
            writeHeader = false;
        }

        lzma.write(buf, offs, len);
    }

    @Override
    public void close() throws IOException {
        lzma.close();
        super.close();
    }

}
