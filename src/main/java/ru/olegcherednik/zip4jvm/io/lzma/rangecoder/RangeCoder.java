package ru.olegcherednik.zip4jvm.io.lzma.rangecoder;

import java.io.Closeable;

/**
 * @author Oleg Cherednik
 * @since 14.02.2020
 */
abstract class RangeCoder implements Closeable {

    protected static final int SHIFT_BITS = 8;
    protected static final int TOP_MASK = 0xFF000000;
    protected static final int BIT_MODEL_TOTAL_BITS = 11;
    protected static final int BIT_MODEL_TOTAL = 1 << BIT_MODEL_TOTAL_BITS;
    protected static final int MOVE_BITS = 5;

}
