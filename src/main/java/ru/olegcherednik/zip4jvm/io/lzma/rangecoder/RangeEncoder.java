package ru.olegcherednik.zip4jvm.io.lzma.rangecoder;

import lombok.Getter;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 14.02.2020
 */
public class RangeEncoder extends RangeCoder {

    public static final short PROB_INIT = (short)(BIT_MODEL_TOTAL / 2);

    private static final int MOVE_REDUCING_BITS = 4;
    private static final int BIT_PRICE_SHIFT_BITS = 4;

    @Getter
    private final DataOutput out;
    private final int[] prices = createPrices();

    private long low;
    private int range = 0xFFFFFFFF;

    /*
     * NOTE: int is OK for LZMA2 because a compressed chunk is not more than 64 KiB, but with LZMA1 there is no chunking so in theory cacheSize can
     * grow very big. To be very safe, use long instead of int since this code is used for LZMA1 too.
     */
    private long cacheSize = 1;
    private byte cache;

    public RangeEncoder(DataOutput out) {
        this.out = out;
    }

    private void shiftLow() throws IOException {
        int lowHi = (int)(low >>> 32);

        if (lowHi != 0 || low < 0xFF000000L) {
            int temp = cache;

            do {
                out.writeByte(temp + lowHi);
                temp = 0xFF;
            } while (--cacheSize != 0);

            cache = (byte)(low >>> 24);
        }

        cacheSize++;
        low = (low & 0x00FFFFFF) << 8;
    }

    public void encodeBit(short[] probs, int index, int bit) throws IOException {
        int prob = probs[index];
        int bound = (range >>> BIT_MODEL_TOTAL_BITS) * prob;

        // NOTE: Any non-zero value for bit is taken as 1.
        if (bit == 0) {
            range = bound;
            probs[index] = (short)(prob + ((BIT_MODEL_TOTAL - prob) >>> MOVE_BITS));
        } else {
            low += bound & 0xFFFFFFFFL;
            range -= bound;
            probs[index] = (short)(prob - (prob >>> MOVE_BITS));
        }

        if ((range & TOP_MASK) == 0) {
            range <<= SHIFT_BITS;
            shiftLow();
        }
    }

    public void encodeBitTree(short[] probs, int symbol) throws IOException {
        int index = 1;
        int mask = probs.length;

        do {
            mask >>>= 1;
            int bit = symbol & mask;
            encodeBit(probs, index, bit);

            index <<= 1;
            if (bit != 0)
                index |= 1;

        } while (mask != 1);
    }

    public int getBitTreePrice(short[] probs, int symbol) {
        int price = 0;
        symbol |= probs.length;

        do {
            int bit = symbol & 1;
            symbol >>>= 1;
            price += getBitPrice(probs[symbol], bit);
        } while (symbol != 1);

        return price;
    }

    public void encodeReverseBitTree(short[] probs, int symbol) throws IOException {
        int index = 1;
        symbol |= probs.length;

        do {
            int bit = symbol & 1;
            symbol >>>= 1;
            encodeBit(probs, index, bit);
            index = (index << 1) | bit;
        } while (symbol != 1);
    }

    public int getBitPrice(int prob, int bit) {
        // NOTE: Unlike in encodeBit(), here bit must be 0 or 1.
        return prices[(prob ^ (-bit & (BIT_MODEL_TOTAL - 1))) >>> MOVE_REDUCING_BITS];
    }

    public void encodeDirectBits(int value, int count) throws IOException {
        do {
            range >>>= 1;
            low += range & -((value >>> --count) & 1);

            if ((range & TOP_MASK) == 0) {
                range <<= SHIFT_BITS;
                shiftLow();
            }
        } while (count != 0);
    }

    public int getReverseBitTreePrice(short[] probs, int symbol) {
        int price = 0;
        int index = 1;
        symbol |= probs.length;

        do {
            int bit = symbol & 1;
            symbol >>>= 1;
            price += getBitPrice(probs[index], bit);
            index = (index << 1) | bit;
        } while (symbol != 1);

        return price;
    }

    @Override
    public void close() throws IOException {
        for (int i = 0; i < 5; ++i)
            shiftLow();
    }

    public static int getDirectBitsPrice(int count) {
        return count << BIT_PRICE_SHIFT_BITS;
    }

    private static int[] createPrices() {
        int[] prices = new int[BIT_MODEL_TOTAL >>> MOVE_REDUCING_BITS];

        for (int i = (1 << MOVE_REDUCING_BITS) / 2; i < BIT_MODEL_TOTAL; i += 1 << MOVE_REDUCING_BITS) {
            int w = i;
            int bitCount = 0;

            for (int j = 0; j < BIT_PRICE_SHIFT_BITS; ++j) {
                w *= w;
                bitCount <<= 1;

                while ((w & 0xFFFF0000) != 0) {
                    w >>>= 1;
                    ++bitCount;
                }
            }

            prices[i >> MOVE_REDUCING_BITS] = (BIT_MODEL_TOTAL_BITS << BIT_PRICE_SHIFT_BITS) - 15 - bitCount;
        }

        return prices;
    }

}
