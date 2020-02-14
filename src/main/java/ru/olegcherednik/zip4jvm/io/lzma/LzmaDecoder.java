package ru.olegcherednik.zip4jvm.io.lzma;

import lombok.Getter;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.lzma.lz.LzDecoder;
import ru.olegcherednik.zip4jvm.io.lzma.rangecoder.RangeDecoder;

import java.io.IOException;
import java.util.stream.IntStream;

/**
 * @author Oleg Cherednik
 * @since 14.02.2020
 */
@Getter
public final class LzmaDecoder extends LzmaCoder {

    private final LzDecoder lz;
    private final RangeDecoder raceDecoder;
    private final LiteralDecoder literalDecoder;
    private final LengthDecoder matchLengthDecoder = new LengthDecoder();
    private final LengthDecoder repLengthDecoder = new LengthDecoder();

    public static LzmaDecoder create(DataInput in) throws IOException {
        return new LzmaDecoder(in, LzmaOutputStream.Properties.read(in));
    }

    private LzmaDecoder(DataInput in, LzmaOutputStream.Properties properties) throws IOException {
        super(properties.getPb());
        lz = new LzDecoder(properties.getDictionarySize());
        raceDecoder = new RangeDecoder(in);
        literalDecoder = new LiteralDecoder(properties);
    }

    /*
     * Returns true if LZMA end marker was detected. It is encoded as the maximum match distance which with signed ints becomes -1. This function is
     * needed only for LZMA1. LZMA2 doesn't use the end marker in the LZMA layer.
     */
    public boolean isEndMarkerDetected() {
        return reps[0] == -1;
    }

    public void decode() throws IOException {
        lz.repeatPending();

        while (lz.hasSpace()) {
            int posState = lz.getPos() & posMask;

            if (raceDecoder.decodeBit(isMatch[state.get()], posState) == 0) {
                literalDecoder.decode();
            } else {
                int len = raceDecoder.decodeBit(isRep, state.get()) == 0 ? decodeMatch(posState) : decodeRepMatch(posState);

                // NOTE: With LZMA1 streams that have the end marker, this will throw CorruptedInputException. LZMAInputStream handles it specially.
                lz.repeat(reps[0], len);
            }
        }

        raceDecoder.normalize();
    }

    private int decodeMatch(int posState) throws IOException {
        state.updateMatch();

        reps[3] = reps[2];
        reps[2] = reps[1];
        reps[1] = reps[0];

        int len = matchLengthDecoder.decode(posState);
        int distSlot = raceDecoder.decodeBitTree(distSlots[getDistState(len)]);

        if (distSlot < DIST_MODEL_START)
            reps[0] = distSlot;
        else {
            int limit = (distSlot >> 1) - 1;
            reps[0] = (2 | (distSlot & 1)) << limit;

            if (distSlot < DIST_MODEL_END)
                reps[0] |= raceDecoder.decodeReverseBitTree(distSpecial[distSlot - DIST_MODEL_START]);
            else {
                reps[0] |= raceDecoder.decodeDirectBits(limit - ALIGN_BITS) << ALIGN_BITS;
                reps[0] |= raceDecoder.decodeReverseBitTree(distAlign);
            }
        }

        return len;
    }

    private int decodeRepMatch(int posState) throws IOException {
        if (raceDecoder.decodeBit(isRep0, state.get()) == 0) {
            if (raceDecoder.decodeBit(isRep0Long[state.get()], posState) == 0) {
                state.updateShortRep();
                return 1;
            }
        } else {
            int tmp;

            if (raceDecoder.decodeBit(isRep1, state.get()) == 0)
                tmp = reps[1];
            else {
                if (raceDecoder.decodeBit(isRep2, state.get()) == 0)
                    tmp = reps[2];
                else {
                    tmp = reps[3];
                    reps[3] = reps[2];
                }

                reps[2] = reps[1];
            }

            reps[1] = reps[0];
            reps[0] = tmp;
        }

        state.updateLongRep();
        return repLengthDecoder.decode(posState);
    }

    @Override
    public void close() throws IOException {
        raceDecoder.close();
    }

    private class LiteralDecoder extends LiteralCoder {

        private final Sub[] sub;

        public LiteralDecoder(LzmaOutputStream.Properties properties) {
            super(properties.getLc(), properties.getLp());
            sub = IntStream.range(0, 1 << (properties.getLc() + properties.getLp())).mapToObj(i -> new Sub()).toArray(Sub[]::new);
        }

        public void decode() throws IOException {
            sub[getSubCoderIndex(lz.getByte(0), lz.getPos())].decode();
        }

        private class Sub {

            private final short[] probs = createArray(0x300);

            public void decode() throws IOException {
                int symbol = 1;

                if (state.isLiteral()) {
                    do {
                        symbol = (symbol << 1) | raceDecoder.decodeBit(probs, symbol);
                    } while (symbol < 0x100);

                } else {
                    int matchByte = lz.getByte(reps[0]);
                    int offset = 0x100;
                    int matchBit;
                    int bit;

                    do {
                        matchByte <<= 1;
                        matchBit = matchByte & offset;
                        bit = raceDecoder.decodeBit(probs, offset + matchBit + symbol);
                        symbol = (symbol << 1) | bit;
                        offset &= -bit ^ ~matchBit;
                    } while (symbol < 0x100);
                }

                lz.putByte((byte)symbol);
                state.updateLiteral();
            }
        }
    }

    private class LengthDecoder extends LengthCoder {

        public int decode(int posState) throws IOException {
            if (raceDecoder.decodeBit(choice, 0) == 0)
                return raceDecoder.decodeBitTree(low[posState]) + MATCH_LEN_MIN;

            if (raceDecoder.decodeBit(choice, 1) == 0)
                return raceDecoder.decodeBitTree(mid[posState]) + MATCH_LEN_MIN + LOW_SYMBOLS;

            return raceDecoder.decodeBitTree(high) + MATCH_LEN_MIN + LOW_SYMBOLS + MID_SYMBOLS;
        }
    }
}
