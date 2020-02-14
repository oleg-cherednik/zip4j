package ru.olegcherednik.zip4jvm.io.in.file;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 22.01.2020
 */
public abstract class LittleEndianDataInputFile implements DataInputFile {

    protected RandomAccessFile in;
    protected long length;

    protected LittleEndianDataInputFile(Path file) throws IOException {
        openNextItem(file);
    }

    @Override
    public final long toLong(byte[] buf, int offs, int len) {
        long res = 0;

        for (int i = offs + len - 1; i >= offs; i--)
            res = res << 8 | buf[i] & 0xFF;

        return res;
    }

    @Override
    public long length() {
        return length;
    }

    @Override
    public long skip(long bytes) throws IOException {
        long skipped = 0;

        while (bytes > 0) {
            int actual = in.skipBytes((int)Math.min(Integer.MAX_VALUE, bytes));

            skipped += actual;
            bytes -= actual;

            if (actual == 0)
                break;
        }

        return skipped;
    }

    @Override
    public void seek(long pos) throws IOException {
        in.seek(pos);
    }

    @Override
    public final void close() throws IOException {
        if (in != null)
            in.close();
    }

    @Override
    public String toString() {
        return "offs: " + getOffs() + " (0x" + Long.toHexString(getOffs()) + ')';
    }

    protected final void openNextItem(Path file) throws IOException {
        close();
        in = new RandomAccessFile(file.toFile(), "r");
        length = in.length();
    }

}
