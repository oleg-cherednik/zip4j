package ru.olegcherednik.zip4jvm.io.in.entry;

import org.apache.commons.io.IOUtils;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.EOFException;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * @author Oleg Cherednik
 * @since 04.08.2019
 */
final class InflateEntryInputStream extends EntryInputStream {

    private final byte[] buf = new byte[1024 * 4];
    private final Inflater inflater = new Inflater(true);

    public InflateEntryInputStream(ZipEntry zipEntry, DataInput in) throws IOException {
        super(zipEntry, in);
    }

    @Override
    public int available() {
        int bytes = super.available();

        if (bytes == 0)
            return inflater.finished() ? 0 : 1;

        return bytes;
    }

    @Override
    public int read(byte[] buf, int offs, int len) throws IOException {
        try {
            int bytes;

            while ((bytes = inflater.inflate(buf, offs, len)) == 0) {
                if (inflater.finished() || inflater.needsDictionary())
                    return IOUtils.EOF;

                if (inflater.needsInput())
                    fill();
            }

            updateChecksum(buf, offs, bytes);
            writtenUncompressedBytes += bytes;
            return bytes;
        } catch(DataFormatException e) {
            throw new IOException(e);
        }
    }

    private void fill() throws IOException {
        int len = (int)Math.min(buf.length, getAvailableCompressedBytes());
        len = in.read(buf, 0, len);

        if (len == IOUtils.EOF)
            throw new EOFException("Unexpected end of ZLIB input stream");

        readCompressedBytes += len;
        inflater.setInput(buf, 0, len);
    }

    @Override
    public void close() throws IOException {
        inflater.end();
        super.close();
    }

}
