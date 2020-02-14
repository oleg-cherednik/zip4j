package ru.olegcherednik.zip4jvm.io.in.file;

import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 21.02.2019
 */
public class LittleEndianReadFile extends LittleEndianDataInputFile {

    public LittleEndianReadFile(Path file) throws IOException {
        super(file);
    }

    @Override
    public int read(byte[] buf, int offs, int len) throws IOException {
        return in.read(buf, offs, len);
    }

    @Override
    public long getOffs() {
        try {
            return in.getFilePointer();
        } catch(IOException e) {
            return IOUtils.EOF;
        }
    }
}
