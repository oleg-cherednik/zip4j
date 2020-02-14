package ru.olegcherednik.zip4jvm.io.in;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 26.01.2020
 */
public interface RandomAccess {

    long skip(long bytes) throws IOException;

    void seek(long pos) throws IOException;

}
