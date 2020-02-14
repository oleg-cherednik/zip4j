package ru.olegcherednik.zip4jvm.io.out.file;

import ru.olegcherednik.zip4jvm.io.out.file.DataOutputFile;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 02.08.2019
 */
public class LittleEndianWriteFile implements DataOutputFile {

    private final RandomAccessFile out;

    public LittleEndianWriteFile(Path file) throws IOException {
        Files.createDirectories(file.getParent());
        out = new RandomAccessFile(file.toFile(), "rw");
    }

    @Override
    public void fromLong(long val, byte[] buf, int offs, int len) {
        for (int i = 0; i < len; i++) {
            buf[offs + i] = (byte)val;
            val >>= 8;
        }
    }

    @Override
    public void write(byte[] buf, int offs, int len) throws IOException {
        out.write(buf, offs, len);
    }

    @Override
    public long getOffs() {
        try {
            return out.getFilePointer();
        } catch(IOException e) {
            return -1;
        }
    }

    @Override
    public void close() throws IOException {
        out.close();
    }

    @Override
    public String toString() {
        return "offs: " + getOffs() + " (0x" + Long.toHexString(getOffs()) + ')';
    }

}
