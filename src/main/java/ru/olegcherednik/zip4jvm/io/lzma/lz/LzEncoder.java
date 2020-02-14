package ru.olegcherednik.zip4jvm.io.lzma.lz;

import lombok.Getter;
import ru.olegcherednik.zip4jvm.io.lzma.LzmaInputStream;

import static ru.olegcherednik.zip4jvm.io.lzma.LzmaEncoder.MATCH_LEN_MAX;

/**
 * @author Oleg Cherednik
 * @since 14.02.2020
 */
public abstract class LzEncoder {

    /** Number of bytes to keep available before the current byte when moving the LZ window. */
    private final int keepSizeBefore;

    /**
     * Number of bytes that must be available, the current byte included, to make hasEnoughData return true. Flushing and finishing are naturally
     * exceptions to this since there cannot be any data after the end of the uncompressed input.
     */
    private final int keepSizeAfter;

    protected final byte[] buf;

    /** The lowest four bits of the absolute offset of the current byte. Bits other than the lowest four are undefined. */
    @Getter
    protected int pos = -1;

    private int readLimit = -1;
    private boolean finishing;
    private int writePos;
    private int pendingSize;

    protected LzEncoder(LzmaInputStream.Properties properties, int extraSizeAfter) {
        buf = createBuffer(properties.getDictionarySize(), extraSizeAfter);
        keepSizeBefore = properties.getDictionarySize();
        keepSizeAfter = extraSizeAfter + MATCH_LEN_MAX;
    }

    private static byte[] createBuffer(int dictSize, int extraSizeAfter) {
        int keepSizeAfter = extraSizeAfter + MATCH_LEN_MAX;
        int reserveSize = Math.min(dictSize / 2 + (256 << 10), 512 << 20);
        int size = dictSize + keepSizeAfter + reserveSize;
        return new byte[size];
    }

    /* Moves data from the end of the buffer to the beginning, discarding old data and making space for new input. */
    private void moveWindow() {
        /*
         * Align the move to a multiple of 16 bytes. LZMA2 needs this because it uses the lowest bits from readPos to get the alignment of the
         * uncompressed data.
         */
        int moveOffset = (pos + 1 - keepSizeBefore) & ~15;
        int moveSize = writePos - moveOffset;
        System.arraycopy(buf, moveOffset, buf, 0, moveSize);

        pos -= moveOffset;
        readLimit -= moveOffset;
        writePos -= moveOffset;
    }

    /* Copies new data into the LZEncoder's buffer. */
    public int fillWindow(byte[] in, int off, int len) {
        // Move the sliding window if needed.
        if (pos >= buf.length - keepSizeAfter)
            moveWindow();

        // Try to fill the dictionary buffer. If it becomes full, some of the input bytes may be left unused.
        if (len > buf.length - writePos)
            len = buf.length - writePos;

        System.arraycopy(in, off, buf, writePos, len);
        writePos += len;

        // Set the new readLimit but only if there's enough data to allow encoding of at least one more byte.
        if (writePos >= keepSizeAfter)
            readLimit = writePos - keepSizeAfter;

        processPendingBytes();

        return len;
    }

    /* Process pending bytes remaining from preset dictionary initialization or encoder flush operation. */
    private void processPendingBytes() {
        /*
         * After flushing or setting a preset dictionary there will be pending data that hasn't been ran through the match finder yet. Run it through
         * the match finder now if there is enough new data available (readPos < readLimit) that the encoder may encode at least one more input byte.
         * This way we don't waste any time looping in the match finder (and marking the same bytes as pending again) if the application provides very
         * little new data per write call.
         */
        if (pendingSize > 0 && pos < readLimit) {
            pos -= pendingSize;
            int oldPendingSize = pendingSize;
            pendingSize = 0;
            skip(oldPendingSize);
            assert pendingSize < oldPendingSize;
        }
    }

    /* Returns true if at least one byte has already been run through he match finder. */
    public boolean isStarted() {
        return pos != -1;
    }

    /* Marks that there is no more input remaining. The read position can be advanced until the end of the data. */
    public void setFinishing() {
        readLimit = writePos - 1;
        finishing = true;
        processPendingBytes();
    }

    /* Tests if there is enough input available to let the caller encode at least one more byte. */
    public boolean hasEnoughData(int alreadyReadLen) {
        return pos - alreadyReadLen < readLimit;
    }

    /*
     * Get the number of bytes available, including the current byte.
     * <p>
     * Note that the result is undefined if <code>getMatches</code> or
     * <code>skip</code> hasn't been called yet and no preset dictionary
     * is being used.
     */
    public int available() {
        return writePos - pos;
    }

    /*
     * Gets the byte from the given forward minus backward offset. The forward offset is added to the current position. This lets one read bytes
     * ahead of the current byte.
     */
    public int getByte(int forward, int backward) {
        return buf[pos + forward - backward] & 0xFF;
    }

    /**
     * Get the length of a match at the given distance and forward offset.
     *
     * @param forward forward offset
     * @param dist    zero-based distance of the match to test
     * @param maxLen  don't test for a match longer than this
     * @return length of the match; it is in the range [0, lenLimit]
     */
    public int getMatchLength(int forward, int dist, int maxLen) {
        int curPos = pos + forward;
        int backPos = curPos - dist - 1;
        int len = 0;

        while (len < maxLen && buf[curPos + len] == buf[backPos + len])
            len++;

        return len;
    }

    /**
     * Moves to the next byte, checks if there is enough input available, and returns the amount of input available.
     *
     * @param requiredForFlushing  minimum number of available bytes when flushing; encoding may be continued with new input after flushing
     * @param requiredForFinishing minimum number of available bytes when finishing; encoding must not be continued after finishing or the match
     *                             finder state may be corrupt
     * @return the number of bytes available or zero if there is not enough input available
     */
    protected int movePos(int requiredForFlushing, int requiredForFinishing) {
        pos++;
        int avail = writePos - pos;

        if (avail < requiredForFlushing) {
            if (avail < requiredForFinishing || !finishing) {
                pendingSize++;
                avail = 0;
            }
        }

        return avail;
    }

    /* Runs match finder for the next byte and returns the matches found. */
    public abstract Matches getMatches();

    /* Skips the given number of bytes in the match finder. */
    public abstract void skip(int len);

    static void normalize(int[] arr, int size, int offs) {
        for (int i = 0; i < size; i++)
            arr[i] = arr[i] <= offs ? 0 : arr[i] - offs;
    }
}
