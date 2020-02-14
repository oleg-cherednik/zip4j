package ru.olegcherednik.zip4jvm.io.lzma;

import ru.olegcherednik.zip4jvm.io.lzma.lz.LzEncoder;
import ru.olegcherednik.zip4jvm.io.lzma.lz.Matches;
import ru.olegcherednik.zip4jvm.io.lzma.rangecoder.RangeEncoder;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

import java.io.IOException;
import java.util.stream.IntStream;

public abstract class LzmaEncoder extends LzmaCoder {

    protected final LzEncoder lz;
    private final RangeEncoder rangeEncoder;
    protected final LiteralEncoder literalEncoder;
    private final LengthEncoder matchLenthEncoder;
    protected final LengthEncoder repLengthEncoder;
    final int niceLength;

    private int distPriceCount;
    private int alignPriceCount;

    private final int distSlotPricesSize;
    private final int[][] distSlotPrices;
    private final int[][] fullDistPrices = new int[DIST_STATES][FULL_DISTANCES];
    private final int[] alignPrices = new int[ALIGN_SIZE];

    int back;
    int readAhead = -1;
    private int uncompressedSize;

    protected LzmaEncoder(DataOutput out, LzEncoder lz, LzmaInputStream.Properties properties) {
        super(properties.getPb());
        this.lz = lz;
        rangeEncoder = new RangeEncoder(out);
        literalEncoder = new LiteralEncoder(properties);
        matchLenthEncoder = new LengthEncoder(properties);
        repLengthEncoder = new LengthEncoder(properties);


        niceLength = properties.getNiceLength();
        distSlotPricesSize = getDistSlot(properties.getDictionarySize() - 1) + 1;
        distSlotPrices = new int[DIST_STATES][distSlotPricesSize];
    }

    /**
     * Gets an integer [0, 63] matching the highest two bits of an integer.
     * This is like bit scan reverse (BSR) on x86 except that this also
     * cares about the second highest bit.
     */
    public static int getDistSlot(int dist) {
        if (dist <= DIST_MODEL_START && dist >= 0)
            return dist;

        int n = dist;
        int i = 31;

        if ((n & 0xFFFF0000) == 0) {
            n <<= 16;
            i = 15;
        }

        if ((n & 0xFF000000) == 0) {
            n <<= 8;
            i -= 8;
        }

        if ((n & 0xF0000000) == 0) {
            n <<= 4;
            i -= 4;
        }

        if ((n & 0xC0000000) == 0) {
            n <<= 2;
            i -= 2;
        }

        if ((n & 0x80000000) == 0)
            --i;

        return (i << 1) + ((dist >>> (i - 1)) & 1);
    }

    public LzEncoder getLZEncoder() {
        return lz;
    }

    /**
     * Gets the next LZMA symbol.
     * <p>
     * There are three types of symbols: literal (a single byte),
     * repeated match, and normal match. The symbol is indicated
     * by the return value and by the variable <code>back</code>.
     * <p>
     * Literal: <code>back == -1</code> and return value is <code>1</code>.
     * The literal itself needs to be read from <code>lz</code> separately.
     * <p>
     * Repeated match: <code>back</code> is in the range [0, 3] and
     * the return value is the length of the repeated match.
     * <p>
     * Normal match: <code>back - REPS<code> (<code>back - 4</code>)
     * is the distance of the match and the return value is the length
     * of the match.
     */
    public abstract int getNextSymbol();

    public int getUncompressedSize() {
        return uncompressedSize;
    }

    /**
     * Compress for LZMA1.
     */
    public void encodeForLZMA1() throws IOException {
        if (lz.isStarted() || encodeInit())
            while (encodeSymbol()) {
            }
    }

    public void encodeLZMA1EndMarker() throws IOException {
        // End of stream marker is encoded as a match with the maximum
        // possible distance. The length is ignored by the decoder,
        // but the minimum length has been used by the LZMA SDK.
        //
        // Distance is a 32-bit unsigned integer in LZMA.
        // With Java's signed int, UINT32_MAX becomes -1.
        int posState = (lz.getPos() - readAhead) & posMask;
        rangeEncoder.encodeBit(isMatch[state.get()], posState, 1);
        rangeEncoder.encodeBit(isRep, state.get(), 0);
        encodeMatch(-1, MATCH_LEN_MIN, posState);
    }

    private boolean encodeInit() throws IOException {
        assert readAhead == -1;
        if (!lz.hasEnoughData(0))
            return false;

        // The first symbol must be a literal unless using
        // a preset dictionary. This code isn't run if using
        // a preset dictionary.
        skip(1);
        rangeEncoder.encodeBit(isMatch[state.get()], 0, 0);
        literalEncoder.encodeInit();

        --readAhead;
        assert readAhead == -1;

        ++uncompressedSize;
        assert uncompressedSize == 1;

        return true;
    }

    private boolean encodeSymbol() throws IOException {
        if (!lz.hasEnoughData(readAhead + 1))
            return false;

        int len = getNextSymbol();

        assert readAhead >= 0;
        int posState = (lz.getPos() - readAhead) & posMask;

        if (back == -1) {
            // Literal i.e. eight-bit byte
            assert len == 1;
            rangeEncoder.encodeBit(isMatch[state.get()], posState, 0);
            literalEncoder.encode();
        } else {
            // Some type of match
            rangeEncoder.encodeBit(isMatch[state.get()], posState, 1);
            if (back < reps.length) {
                // Repeated match i.e. the same distance
                // has been used earlier.
                assert lz.getMatchLen(-readAhead, reps[back], len) == len;
                rangeEncoder.encodeBit(isRep, state.get(), 1);
                encodeRepMatch(back, len, posState);
            } else {
                // Normal match
                assert lz.getMatchLen(-readAhead, back - reps.length, len) == len;
                rangeEncoder.encodeBit(isRep, state.get(), 0);
                encodeMatch(back - reps.length, len, posState);
            }
        }

        readAhead -= len;
        uncompressedSize += len;

        return true;
    }

    private void encodeMatch(int dist, int len, int posState)
            throws IOException {
        state.updateMatch();
        matchLenthEncoder.encode(len, posState);

        int distSlot = getDistSlot(dist);
        rangeEncoder.encodeBitTree(distSlots[getDistState(len)], distSlot);

        if (distSlot >= DIST_MODEL_START) {
            int footerBits = (distSlot >>> 1) - 1;
            int base = (2 | (distSlot & 1)) << footerBits;
            int distReduced = dist - base;

            if (distSlot < DIST_MODEL_END) {
                rangeEncoder.encodeReverseBitTree(
                        distSpecial[distSlot - DIST_MODEL_START],
                        distReduced);
            } else {
                rangeEncoder.encodeDirectBits(distReduced >>> ALIGN_BITS,
                        footerBits - ALIGN_BITS);
                rangeEncoder.encodeReverseBitTree(distAlign, distReduced & ALIGN_MASK);
                --alignPriceCount;
            }
        }

        reps[3] = reps[2];
        reps[2] = reps[1];
        reps[1] = reps[0];
        reps[0] = dist;

        --distPriceCount;
    }

    private void encodeRepMatch(int rep, int len, int posState)
            throws IOException {
        if (rep == 0) {
            rangeEncoder.encodeBit(isRep0, state.get(), 0);
            rangeEncoder.encodeBit(isRep0Long[state.get()], posState, len == 1 ? 0 : 1);
        } else {
            int dist = reps[rep];
            rangeEncoder.encodeBit(isRep0, state.get(), 1);

            if (rep == 1) {
                rangeEncoder.encodeBit(isRep1, state.get(), 0);
            } else {
                rangeEncoder.encodeBit(isRep1, state.get(), 1);
                rangeEncoder.encodeBit(isRep2, state.get(), rep - 2);

                if (rep == 3)
                    reps[3] = reps[2];

                reps[2] = reps[1];
            }

            reps[1] = reps[0];
            reps[0] = dist;
        }

        if (len == 1) {
            state.updateShortRep();
        } else {
            repLengthEncoder.encode(len, posState);
            state.updateLongRep();
        }
    }

    Matches getMatches() {
        ++readAhead;
        Matches matches = lz.getMatches();
        assert lz.verifyMatches(matches);
        return matches;
    }

    void skip(int len) {
        readAhead += len;
        lz.skip(len);
    }

    int getAnyMatchPrice(State state, int posState) {
        return RangeEncoder.getBitPrice(isMatch[state.get()][posState], 1);
    }

    int getNormalMatchPrice(int anyMatchPrice, State state) {
        return anyMatchPrice
                + RangeEncoder.getBitPrice(isRep[state.get()], 0);
    }

    int getAnyRepPrice(int anyMatchPrice, State state) {
        return anyMatchPrice
                + RangeEncoder.getBitPrice(isRep[state.get()], 1);
    }

    int getShortRepPrice(int anyRepPrice, State state, int posState) {
        return anyRepPrice
                + RangeEncoder.getBitPrice(isRep0[state.get()], 0)
                + RangeEncoder.getBitPrice(isRep0Long[state.get()][posState],
                0);
    }

    int getLongRepPrice(int anyRepPrice, int rep, State state, int posState) {
        int price = anyRepPrice;

        if (rep == 0) {
            price += RangeEncoder.getBitPrice(isRep0[state.get()], 0)
                    + RangeEncoder.getBitPrice(
                    isRep0Long[state.get()][posState], 1);
        } else {
            price += RangeEncoder.getBitPrice(isRep0[state.get()], 1);

            if (rep == 1)
                price += RangeEncoder.getBitPrice(isRep1[state.get()], 0);
            else
                price += RangeEncoder.getBitPrice(isRep1[state.get()], 1)
                        + RangeEncoder.getBitPrice(isRep2[state.get()],
                        rep - 2);
        }

        return price;
    }

    int getLongRepAndLenPrice(int rep, int len, State state, int posState) {
        int anyMatchPrice = getAnyMatchPrice(state, posState);
        int anyRepPrice = getAnyRepPrice(anyMatchPrice, state);
        int longRepPrice = getLongRepPrice(anyRepPrice, rep, state, posState);
        return longRepPrice + repLengthEncoder.getPrice(len, posState);
    }

    int getMatchAndLenPrice(int normalMatchPrice,
            int dist, int len, int posState) {
        int price = normalMatchPrice
                + matchLenthEncoder.getPrice(len, posState);
        int distState = getDistState(len);

        if (dist < FULL_DISTANCES) {
            price += fullDistPrices[distState][dist];
        } else {
            // Note that distSlotPrices includes also
            // the price of direct bits.
            int distSlot = getDistSlot(dist);
            price += distSlotPrices[distState][distSlot]
                    + alignPrices[dist & ALIGN_MASK];
        }

        return price;
    }

    private void updateDistPrices() {
        distPriceCount = FULL_DISTANCES;

        for (int distState = 0; distState < DIST_STATES; ++distState) {
            for (int distSlot = 0; distSlot < distSlotPricesSize; ++distSlot)
                distSlotPrices[distState][distSlot]
                        = RangeEncoder.getBitTreePrice(
                        distSlots[distState], distSlot);

            for (int distSlot = DIST_MODEL_END; distSlot < distSlotPricesSize;
                 ++distSlot) {
                int count = (distSlot >>> 1) - 1 - ALIGN_BITS;
                distSlotPrices[distState][distSlot]
                        += RangeEncoder.getDirectBitsPrice(count);
            }

            for (int dist = 0; dist < DIST_MODEL_START; ++dist)
                fullDistPrices[distState][dist]
                        = distSlotPrices[distState][dist];
        }

        int dist = DIST_MODEL_START;
        for (int distSlot = DIST_MODEL_START; distSlot < DIST_MODEL_END;
             ++distSlot) {
            int footerBits = (distSlot >>> 1) - 1;
            int base = (2 | (distSlot & 1)) << footerBits;

            int limit = distSpecial[distSlot - DIST_MODEL_START].length;
            for (int i = 0; i < limit; ++i) {
                int distReduced = dist - base;
                int price = RangeEncoder.getReverseBitTreePrice(
                        distSpecial[distSlot - DIST_MODEL_START],
                        distReduced);

                for (int distState = 0; distState < DIST_STATES; ++distState)
                    fullDistPrices[distState][dist]
                            = distSlotPrices[distState][distSlot] + price;

                ++dist;
            }
        }

        assert dist == FULL_DISTANCES;
    }

    private void updateAlignPrices() {
        alignPriceCount = ALIGN_SIZE;

        for (int i = 0; i < ALIGN_SIZE; ++i)
            alignPrices[i] = RangeEncoder.getReverseBitTreePrice(distAlign, i);
    }

    /**
     * Updates the lookup tables used for calculating match distance and length prices. The updating is skipped for performance reasons if the tables
     * haven't changed much since the previous update.
     */
    public void updatePrices() {
        if (distPriceCount <= 0)
            updateDistPrices();

        if (alignPriceCount <= 0)
            updateAlignPrices();

        matchLenthEncoder.updatePrices();
        repLengthEncoder.updatePrices();
    }

    public void finish() throws IOException {
        rangeEncoder.finish();
    }

    protected class LiteralEncoder extends LiteralCoder {

        private final Sub[] sub;

        public LiteralEncoder(LzmaInputStream.Properties properties) {
            super(properties.getLc(), properties.getLp());
            sub = IntStream.range(0, 1 << (properties.getLc() + properties.getLp()))
                           .mapToObj(i -> new Sub())
                           .toArray(Sub[]::new);
        }

        public void encodeInit() throws IOException {
            // When encoding the first byte of the stream, there is no previous byte in the dictionary so the encode function wouldn't work.
            sub[0].encode();
        }

        public void encode() throws IOException {
            sub[getSubCoderIndex(lz.getByte(1 + readAhead), lz.getPos() - readAhead)].encode();
        }

        public int getPrice(int curByte, int matchByte, int prevByte, int pos, State state) {
            int price = RangeEncoder.getBitPrice(isMatch[state.get()][pos & posMask], 0);

            int i = getSubCoderIndex(prevByte, pos);
            price += state.isLiteral() ? sub[i].getNormalPrice(curByte) : sub[i].getMatchedPrice(curByte, matchByte);

            return price;
        }

        private class Sub {

            private final short[] probs = createArray(0x300);

            public void encode() throws IOException {
                int symbol = lz.getByte(readAhead) | 0x100;

                if (state.isLiteral()) {
                    int subencoderIndex;
                    int bit;

                    do {
                        subencoderIndex = symbol >>> 8;
                        bit = (symbol >>> 7) & 1;
                        rangeEncoder.encodeBit(probs, subencoderIndex, bit);
                        symbol <<= 1;
                    } while (symbol < 0x10000);

                } else {
                    int matchByte = lz.getByte(reps[0] + 1 + readAhead);
                    int offset = 0x100;
                    int subencoderIndex;
                    int matchBit;
                    int bit;

                    do {
                        matchByte <<= 1;
                        matchBit = matchByte & offset;
                        subencoderIndex = offset + matchBit + (symbol >>> 8);
                        bit = (symbol >>> 7) & 1;
                        rangeEncoder.encodeBit(probs, subencoderIndex, bit);
                        symbol <<= 1;
                        offset &= ~(matchByte ^ symbol);
                    } while (symbol < 0x10000);
                }

                state.updateLiteral();
            }

            public int getNormalPrice(int symbol) {
                int price = 0;
                int subencoderIndex;
                int bit;

                symbol |= 0x100;

                do {
                    subencoderIndex = symbol >>> 8;
                    bit = (symbol >>> 7) & 1;
                    price += RangeEncoder.getBitPrice(probs[subencoderIndex],
                            bit);
                    symbol <<= 1;
                } while (symbol < (0x100 << 8));

                return price;
            }

            public int getMatchedPrice(int symbol, int matchByte) {
                int price = 0;
                int offset = 0x100;
                int subencoderIndex;
                int matchBit;
                int bit;

                symbol |= 0x100;

                do {
                    matchByte <<= 1;
                    matchBit = matchByte & offset;
                    subencoderIndex = offset + matchBit + (symbol >>> 8);
                    bit = (symbol >>> 7) & 1;
                    price += RangeEncoder.getBitPrice(probs[subencoderIndex],
                            bit);
                    symbol <<= 1;
                    offset &= ~(matchByte ^ symbol);
                } while (symbol < (0x100 << 8));

                return price;
            }
        }
    }

    protected class LengthEncoder extends LengthCoder {

        /** The prices are updated after at least <code>PRICE_UPDATE_INTERVAL</code> many lengths have been encoded with the same posState. */
        private static final int PRICE_UPDATE_INTERVAL = 32;

        private final int[] counters;
        private final int[][] prices;

        public LengthEncoder(LzmaInputStream.Properties properties) {
            counters = new int[1 << properties.getPb()];

            // Always allocate at least LOW_SYMBOLS + MID_SYMBOLS because it makes updatePrices slightly simpler. The prices aren't usually needed
            // anyway if niceLen < 18.
            int lenSymbols = Math.max(properties.getNiceLength() - MATCH_LEN_MIN + 1, LOW_SYMBOLS + MID_SYMBOLS);
            prices = new int[counters.length][lenSymbols];
        }

        public void encode(int len, int posState) throws IOException {
            len -= MATCH_LEN_MIN;

            if (len < LOW_SYMBOLS) {
                rangeEncoder.encodeBit(choice, 0, 0);
                rangeEncoder.encodeBitTree(low[posState], len);
            } else {
                rangeEncoder.encodeBit(choice, 0, 1);
                len -= LOW_SYMBOLS;

                if (len < MID_SYMBOLS) {
                    rangeEncoder.encodeBit(choice, 1, 0);
                    rangeEncoder.encodeBitTree(mid[posState], len);
                } else {
                    rangeEncoder.encodeBit(choice, 1, 1);
                    rangeEncoder.encodeBitTree(high, len - MID_SYMBOLS);
                }
            }

            --counters[posState];
        }

        public int getPrice(int len, int posState) {
            return prices[posState][len - MATCH_LEN_MIN];
        }

        public void updatePrices() {
            for (int posState = 0; posState < counters.length; ++posState) {
                if (counters[posState] > 0)
                    continue;

                counters[posState] = PRICE_UPDATE_INTERVAL;
                updatePrices(posState);
            }
        }

        private void updatePrices(int posState) {
            int zero = RangeEncoder.getBitPrice(choice[0], 0);

            int i = 0;
            for (; i < LOW_SYMBOLS; i++)
                prices[posState][i] = zero + RangeEncoder.getBitTreePrice(low[posState], i);

            zero = RangeEncoder.getBitPrice(choice[0], 1);
            int one = RangeEncoder.getBitPrice(choice[1], 0);

            for (; i < LOW_SYMBOLS + MID_SYMBOLS; i++)
                prices[posState][i] = zero + one + RangeEncoder.getBitTreePrice(mid[posState], i - LOW_SYMBOLS);

            one = RangeEncoder.getBitPrice(choice[1], 1);

            for (; i < prices[posState].length; i++)
                prices[posState][i] = zero + one + RangeEncoder.getBitTreePrice(high, i - LOW_SYMBOLS - MID_SYMBOLS);
        }
    }
}
