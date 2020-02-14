package ru.olegcherednik.zip4jvm.io.out.file;

import java.io.Closeable;
import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 08.08.2019
 */
public interface DataOutputFile extends Closeable {

    void write(byte[] buf, int offs, int len) throws IOException;

    long getOffs();

    void fromLong(long val, byte[] buf, int offs, int len);

}
