package ru.olegcherednik.zip4jvm.crypto.pkware;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.exception.IncorrectPasswordException;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;
import java.util.Random;

/**
 * @author Oleg Cherednik
 * @since 29.07.2019
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class PkwareHeader {

    public static final int SIZE = 12;

    private final byte[] buf;

    public static PkwareHeader create(PkwareEngine engine, int checksum) {
        return new PkwareHeader(createBuf(engine, checksum));
    }

    private static byte[] createBuf(PkwareEngine engine, int checksum) {
        byte[] buf = new byte[SIZE];

        new Random().nextBytes(buf);
        buf[buf.length - 1] = low(checksum);
        buf[buf.length - 2] = high(checksum);
        engine.encrypt(buf, 0, buf.length);

        return buf;
    }

    public static PkwareHeader read(PkwareEngine engine, ZipEntry zipEntry, DataInput in) throws IOException {
        PkwareHeader header = new PkwareHeader(in.readBytes(SIZE));
        header.requireMatchChecksum(engine, zipEntry);
        return header;
    }

    public void write(DataOutput out) throws IOException {
        out.writeBytes(buf);
    }

    /** see 6.1.6 */
    private void requireMatchChecksum(PkwareEngine engine, ZipEntry zipEntry) {
        engine.decrypt(buf, 0, buf.length);
        int checksum = getChecksum(zipEntry);

        if (buf[buf.length - 1] != low(checksum) /*|| buf[buf.length - 2] != high(checksum)*/)
            throw new IncorrectPasswordException(zipEntry.getFileName());
    }

    private static int getChecksum(ZipEntry zipEntry) {
        return zipEntry.getLastModifiedTime();
    }

    private static byte low(int checksum) {
        return (byte)(checksum >> 8);
    }

    private static byte high(int checksum) {
        return (byte)checksum;
    }

}
