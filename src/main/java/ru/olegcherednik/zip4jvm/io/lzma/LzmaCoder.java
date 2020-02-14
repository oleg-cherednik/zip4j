package ru.olegcherednik.zip4jvm.io.lzma;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.io.Closeable;
import java.io.IOException;
import java.util.Arrays;

import static ru.olegcherednik.zip4jvm.io.lzma.rangecoder.RangeEncoder.PROB_INIT;

/**
 * @author Oleg Cherednik
 * @since 14.02.2020
 */
@SuppressWarnings("MethodCanBeVariableArityMethod")
abstract class LzmaCoder implements Closeable {

    private static final int POS_STATES_MAX = 1 << 4;

    protected static final int DIST_STATES = 4;
    protected static final int DIST_MODEL_START = 4;
    protected static final int DIST_MODEL_END = 14;

    protected static final int ALIGN_BITS = 4;
    protected static final int ALIGN_SIZE = 1 << ALIGN_BITS;

    protected static final int MATCH_LEN_MIN = 2;

    protected final int posMask;
    protected final int[] reps = new int[4];
    protected final State state = new State();

    protected final short[][] isMatch = createArray(State.STATES, POS_STATES_MAX);
    protected final short[] isRep = createArray(State.STATES);
    protected final short[] isRep0 = createArray(State.STATES);
    protected final short[] isRep1 = createArray(State.STATES);
    protected final short[] isRep2 = createArray(State.STATES);
    protected final short[][] isRep0Long = createArray(State.STATES, POS_STATES_MAX);
    protected final short[][] distSlots = createArray(DIST_STATES, 1 << 6);
    protected final short[] distAlign = createArray(ALIGN_SIZE);

    final short[][] distSpecial = { new short[2], new short[2],
            new short[4], new short[4],
            new short[8], new short[8],
            new short[16], new short[16],
            new short[32], new short[32] };

    protected LzmaCoder(int pb) {
        posMask = (1 << pb) - 1;

        for (int i = 0; i < distSpecial.length; ++i)
            initProbs(distSpecial[i]);
    }

    protected static int getDistState(int len) {
        return len < DIST_STATES + MATCH_LEN_MIN ? len - MATCH_LEN_MIN : DIST_STATES - 1;
    }

    private static void initProbs(short[] probs) {
        Arrays.fill(probs, PROB_INIT);
    }

    protected static short[] createArray(int size) {
        short[] arr = new short[size];
        initProbs(arr);
        return arr;
    }

    private static short[][] createArray(int rows, int cols) {
        short[][] arr = new short[rows][cols];

        for (short[] line : arr)
            initProbs(line);

        return arr;
    }

    protected abstract static class LiteralCoder {

        private final int lc;
        private final int literalPosMask;

        protected LiteralCoder(int lc, int lp) {
            this.lc = lc;
            literalPosMask = (1 << lp) - 1;
        }

        protected final int getSubCoderIndex(int prvByte, int pos) {
            int low = prvByte >> (8 - lc);
            int high = (pos & literalPosMask) << lc;
            return low + high;
        }
    }

    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    protected abstract static class LengthCoder {

        protected static final int LOW_SYMBOLS = 1 << 3;
        protected static final int MID_SYMBOLS = 1 << 3;
        protected static final int HIGH_SYMBOLS = 1 << 8;

        protected final short[] choice = createArray(2);
        protected final short[][] low = createArray(POS_STATES_MAX, LOW_SYMBOLS);
        protected final short[][] mid = createArray(POS_STATES_MAX, MID_SYMBOLS);
        protected final short[] high = createArray(HIGH_SYMBOLS);

    }

    @Override
    public void close() throws IOException {
    }
}
