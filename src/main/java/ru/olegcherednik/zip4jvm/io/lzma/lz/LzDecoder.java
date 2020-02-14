package ru.olegcherednik.zip4jvm.io.lzma.lz;

import ru.olegcherednik.zip4jvm.io.lzma.LzmaCorruptedInputException;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 14.02.2020
 */
public final class LzDecoder {

    private final byte[] buf;

    private int start;
    private int pos;
    private int full;
    private int limit;
    private int pendingLen;
    private int pendingDist;

    public LzDecoder(int size) {
        buf = new byte[size];
    }

    public void setLimit(int outMax) {
        limit = buf.length - pos <= outMax ? buf.length : pos + outMax;
    }

    public boolean hasSpace() {
        return pos < limit;
    }

    public boolean hasPending() {
        return pendingLen > 0;
    }

    public int getPos() {
        return pos;
    }

    public int getByte(int dist) {
        int offs = pos - dist - 1;

        if (dist >= pos)
            offs += buf.length;

        return buf[offs] & 0xFF;
    }

    public void putByte(byte b) {
        buf[pos++] = b;

        if (full < pos)
            full = pos;
    }

    public void repeat(int dist, int len) throws IOException {
        if (dist < 0 || dist >= full)
            throw new LzmaCorruptedInputException();

        int left = Math.min(limit - pos, len);
        pendingLen = len - left;
        pendingDist = dist;

        int back = pos - dist - 1;
        if (dist >= pos)
            back += buf.length;

        do {
            buf[pos++] = buf[back++];
            if (back == buf.length)
                back = 0;
        } while (--left > 0);

        if (full < pos)
            full = pos;
    }

    public void repeatPending() throws IOException {
        if (pendingLen > 0)
            repeat(pendingDist, pendingLen);
    }

    public int flush(byte[] out, int outOff) {
        int copySize = pos - start;
        if (pos == buf.length)
            pos = 0;

        System.arraycopy(buf, start, out, outOff, copySize);
        start = pos;

        return copySize;
    }
}
