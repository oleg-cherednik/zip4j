package ru.olegcherednik.zip4jvm.io.lzma;

import ru.olegcherednik.zip4jvm.io.lzma.lz.LzEncoder;
import ru.olegcherednik.zip4jvm.io.lzma.lz.Matches;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

import java.util.stream.IntStream;

/**
 * @author Oleg Cherednik
 * @since 14.02.2020
 */
final class LzmaEncoderNormal extends LzmaEncoder {

    private static final int OPTS = 4096;

    private final int niceLength;

    private final Optimum[] opts = IntStream.range(0, OPTS).mapToObj(i -> new Optimum()).toArray(Optimum[]::new);
    private int optCur;
    private int optEnd;

    private Matches matches;

    // These are fields solely to avoid allocating the objects again and again on each function call.
    private final int[] repLens = new int[4];
    private final State nextState = new State();

    public LzmaEncoderNormal(DataOutput out, LzmaInputStream.Properties properties) {
        super(out, createEncoder(properties), properties);
        niceLength = properties.getNiceLength();
    }

    private static LzEncoder createEncoder(LzmaInputStream.Properties properties) {
        return properties.getMatchFinder().createEncoder(properties, OPTS);
    }

    /**
     * Converts the opts array from backward indexes to forward indexes.
     * Then it will be simple to get the next symbol from the array
     * in later calls to <code>getNextSymbol()</code>.
     */
    private int convertOpts() {
        optEnd = optCur;

        int optPrev = opts[optCur].optPrev;

        do {
            Optimum opt = opts[optCur];

            if (opt.prev1IsLiteral) {
                opts[optPrev].optPrev = optCur;
                opts[optPrev].backPrev = -1;
                optCur = optPrev--;

                if (opt.hasPrev2) {
                    opts[optPrev].optPrev = optPrev + 1;
                    opts[optPrev].backPrev = opt.backPrev2;
                    optCur = optPrev;
                    optPrev = opt.optPrev2;
                }
            }

            int temp = opts[optPrev].optPrev;
            opts[optPrev].optPrev = optCur;
            optCur = optPrev;
            optPrev = temp;
        } while (optCur > 0);

        optCur = opts[0].optPrev;
        back = opts[optCur].backPrev;
        return optCur;
    }

    @Override
    public int getNextSymbol() {
        // If there are pending symbols from an earlier call to this function, return those symbols first.
        if (optCur < optEnd) {
            int len = opts[optCur].optPrev - optCur;
            optCur = opts[optCur].optPrev;
            back = opts[optCur].backPrev;
            return len;
        }

        optCur = 0;
        optEnd = 0;
        back = -1;

        if (readAhead == -1)
            matches = getMatches();

        /*
         * Get the number of bytes available in the dictionary, but not more than the maximum match length. If there aren't enough bytes remaining to
         * encode a match at all, return immediately to encode this byte as a literal.
         */
        int avail = Math.min(lz.available(), MATCH_LEN_MAX);
        if (avail < MATCH_LEN_MIN)
            return 1;

        // Get the lengths of repeated matches.
        int repBest = 0;
        for (int rep = 0; rep < reps.length; ++rep) {
            repLens[rep] = lz.getMatchLength(0, reps[rep], avail);

            if (repLens[rep] < MATCH_LEN_MIN) {
                repLens[rep] = 0;
                continue;
            }

            if (repLens[rep] > repLens[repBest])
                repBest = rep;
        }

        // Return if the best repeated match is at least niceLen bytes long.
        if (repLens[repBest] >= niceLength) {
            back = repBest;
            skip(repLens[repBest] - 1);
            return repLens[repBest];
        }

        // Initialize mainLen and mainDist to the longest match found by the match finder.
        int mainLen = 0;
        int mainDist = 0;
        if (matches.getCount() > 0) {
            mainLen = matches.getLen()[matches.getCount() - 1];
            mainDist = matches.getDist()[matches.getCount() - 1];

            // Return if it is at least niceLen bytes long.
            if (mainLen >= niceLength) {
                back = mainDist + reps.length;
                skip(mainLen - 1);
                return mainLen;
            }
        }

        int curByte = lz.getByte(0, 0);
        int matchByte = lz.getByte(0, reps[0] + 1);

        /*
         * If the match finder found no matches and this byte cannot be encoded as a repeated match (short or long), we must be return to have the
         * byte encoded as a literal.
         */
        if (mainLen < MATCH_LEN_MIN && curByte != matchByte && repLens[repBest] < MATCH_LEN_MIN)
            return 1;

        int pos = lz.getPos();
        int posState = pos & posMask;

        // Calculate the price of encoding the current byte as a literal.
        int prevByte = lz.getByte(0, 1);
        int literalPrice = literalEncoder.getPrice(curByte, matchByte, prevByte, pos, state);
        opts[1].set1(literalPrice, 0, -1);

        int anyMatchPrice = getAnyMatchPrice(state, posState);
        int anyRepPrice = getAnyRepPrice(anyMatchPrice, state);

        // If it is possible to encode this byte as a short rep, see if it is cheaper than encoding it as a literal.
        if (matchByte == curByte) {
            int shortRepPrice = getShortRepPrice(anyRepPrice, state, posState);
            if (shortRepPrice < opts[1].price)
                opts[1].set1(shortRepPrice, 0, 0);
        }

        // Return if there is neither normal nor long repeated match. Use a short match instead of a literal if is is possible and cheaper.
        optEnd = Math.max(mainLen, repLens[repBest]);
        if (optEnd < MATCH_LEN_MIN) {
            back = opts[1].backPrev;
            return 1;
        }

        /*
         * Update the lookup tables for distances and lengths before using those price calculation functions. (The price function above don't need
         * these tables.)
         */
        updatePrices();

        /*
         * Initialize the state and reps of this position in opts[].
         * updateOptStateAndReps() will need these to get the new state and reps for the next byte.
         */
        opts[0].state.set(state);
        System.arraycopy(reps, 0, opts[0].reps, 0, reps.length);

        // Initialize the prices for latter opts that will be used below.
        for (int i = optEnd; i >= MATCH_LEN_MIN; --i)
            opts[i].reset();

        // Calculate the prices of repeated matches of all lengths.
        for (int rep = 0; rep < reps.length; ++rep) {
            int repLen = repLens[rep];
            if (repLen < MATCH_LEN_MIN)
                continue;

            int longRepPrice = getLongRepPrice(anyRepPrice, rep,
                    state, posState);
            do {
                int price = longRepPrice + repLengthEncoder.getPrice(repLen, posState);
                if (price < opts[repLen].price)
                    opts[repLen].set1(price, 0, rep);
            } while (--repLen >= MATCH_LEN_MIN);
        }

        // Calculate the prices of normal matches that are longer than rep0.
        int len = Math.max(repLens[0] + 1, MATCH_LEN_MIN);
        if (len <= mainLen) {
            int normalMatchPrice = getNormalMatchPrice(anyMatchPrice,
                    state);

            // Set i to the index of the shortest match that is at least len bytes long.
            int i = 0;
            while (len > matches.getLen()[i])
                i++;

            while (true) {
                int dist = matches.getDist()[i];
                int price = getMatchAndLenPrice(normalMatchPrice, dist, len, posState);
                if (price < opts[len].price)
                    opts[len].set1(price, 0, dist + reps.length);

                if (len == matches.getLen()[i])
                    if (++i == matches.getCount())
                        break;

                len++;
            }
        }

        avail = Math.min(lz.available(), OPTS - 1);

        // Get matches for later bytes and optimize the use of LZMA symbols by calculating the prices and picking the cheapest symbol combinations.
        while (++optCur < optEnd) {
            matches = getMatches();
            if (matches.getCount() > 0 && matches.getLen()[matches.getCount() - 1] >= niceLength)
                break;

            avail--;
            pos++;
            posState = pos & posMask;

            updateOptStateAndReps();
            anyMatchPrice = opts[optCur].price + getAnyMatchPrice(opts[optCur].state, posState);
            anyRepPrice = getAnyRepPrice(anyMatchPrice, opts[optCur].state);

            calc1BytePrices(pos, posState, avail, anyRepPrice);

            if (avail >= MATCH_LEN_MIN) {
                int startLen = calcLongRepPrices(pos, posState, avail, anyRepPrice);
                if (matches.getCount() > 0)
                    calcNormalMatchPrices(pos, posState, avail, anyMatchPrice, startLen);
            }
        }

        return convertOpts();
    }

    /** Updates the state and reps for the current byte in the opts array. */
    private void updateOptStateAndReps() {
        int optPrev = opts[optCur].optPrev;

        if (opts[optCur].prev1IsLiteral) {
            optPrev--;

            if (opts[optCur].hasPrev2) {
                opts[optCur].state.set(opts[opts[optCur].optPrev2].state);
                if (opts[optCur].backPrev2 < reps.length)
                    opts[optCur].state.updateLongRep();
                else
                    opts[optCur].state.updateMatch();
            } else
                opts[optCur].state.set(opts[optPrev].state);

            opts[optCur].state.updateLiteral();
        } else
            opts[optCur].state.set(opts[optPrev].state);

        if (optPrev == optCur - 1) {
            // Must be either a short rep or a literal.
            assert opts[optCur].backPrev == 0 || opts[optCur].backPrev == -1;

            if (opts[optCur].backPrev == 0)
                opts[optCur].state.updateShortRep();
            else
                opts[optCur].state.updateLiteral();

            System.arraycopy(opts[optPrev].reps, 0, opts[optCur].reps, 0, reps.length);
        } else {
            int back;
            if (opts[optCur].prev1IsLiteral && opts[optCur].hasPrev2) {
                optPrev = opts[optCur].optPrev2;
                back = opts[optCur].backPrev2;
                opts[optCur].state.updateLongRep();
            } else {
                back = opts[optCur].backPrev;
                if (back < reps.length)
                    opts[optCur].state.updateLongRep();
                else
                    opts[optCur].state.updateMatch();
            }

            if (back < reps.length) {
                opts[optCur].reps[0] = opts[optPrev].reps[back];

                int rep;
                for (rep = 1; rep <= back; ++rep)
                    opts[optCur].reps[rep] = opts[optPrev].reps[rep - 1];

                for (; rep < reps.length; ++rep)
                    opts[optCur].reps[rep] = opts[optPrev].reps[rep];
            } else {
                opts[optCur].reps[0] = back - reps.length;
                System.arraycopy(opts[optPrev].reps, 0, opts[optCur].reps, 1, reps.length - 1);
            }
        }
    }

    /** Calculates prices of a literal, a short rep, and literal + rep0. */
    private void calc1BytePrices(int pos, int posState, int avail, int anyRepPrice) {
        // This will be set to true if using a literal or a short rep.
        boolean nextIsByte = false;
        int curByte = lz.getByte(0, 0);
        int matchByte = lz.getByte(0, opts[optCur].reps[0] + 1);

        // Try a literal.
        int literalPrice = opts[optCur].price + literalEncoder.getPrice(curByte, matchByte, lz.getByte(0, 1), pos, opts[optCur].state);

        if (literalPrice < opts[optCur + 1].price) {
            opts[optCur + 1].set1(literalPrice, optCur, -1);
            nextIsByte = true;
        }

        // Try a short rep.
        if (matchByte == curByte && (opts[optCur + 1].optPrev == optCur || opts[optCur + 1].backPrev != 0)) {
            int shortRepPrice = getShortRepPrice(anyRepPrice, opts[optCur].state, posState);
            if (shortRepPrice <= opts[optCur + 1].price) {
                opts[optCur + 1].set1(shortRepPrice, optCur, 0);
                nextIsByte = true;
            }
        }

        // If neither a literal nor a short rep was the cheapest choice,  try literal + long rep0.
        if (!nextIsByte && matchByte != curByte && avail > MATCH_LEN_MIN) {
            int lenLimit = Math.min(niceLength, avail - 1);
            int len = lz.getMatchLength(1, opts[optCur].reps[0], lenLimit);

            if (len >= MATCH_LEN_MIN) {
                nextState.set(opts[optCur].state);
                nextState.updateLiteral();
                int nextPosState = (pos + 1) & posMask;
                int price = literalPrice + getLongRepAndLenPrice(0, len, nextState, nextPosState);

                int i = optCur + 1 + len;
                while (optEnd < i)
                    opts[++optEnd].reset();

                if (price < opts[i].price)
                    opts[i].set2(price, optCur, 0);
            }
        }
    }

    private int getShortRepPrice(int anyRepPrice, State state, int posState) {
        return anyRepPrice + rangeEncoder.getBitPrice(isRep0[state.get()], 0) + rangeEncoder.getBitPrice(isRep0Long[state.get()][posState], 0);
    }

    private int getLongRepAndLenPrice(int rep, int len, State state, int posState) {
        int anyMatchPrice = getAnyMatchPrice(state, posState);
        int anyRepPrice = getAnyRepPrice(anyMatchPrice, state);
        int longRepPrice = getLongRepPrice(anyRepPrice, rep, state, posState);
        return longRepPrice + repLengthEncoder.getPrice(len, posState);
    }

    /** Calculates prices of long rep and long rep + literal + rep0. */
    private int calcLongRepPrices(int pos, int posState, int avail, int anyRepPrice) {
        int startLen = MATCH_LEN_MIN;
        int lenLimit = Math.min(avail, niceLength);

        for (int rep = 0; rep < reps.length; ++rep) {
            int len = lz.getMatchLength(0, opts[optCur].reps[rep], lenLimit);
            if (len < MATCH_LEN_MIN)
                continue;

            while (optEnd < optCur + len)
                opts[++optEnd].reset();

            int longRepPrice = getLongRepPrice(anyRepPrice, rep, opts[optCur].state, posState);

            for (int i = len; i >= MATCH_LEN_MIN; --i) {
                int price = longRepPrice + repLengthEncoder.getPrice(i, posState);

                if (price < opts[optCur + i].price)
                    opts[optCur + i].set1(price, optCur, rep);
            }

            if (rep == 0)
                startLen = len + 1;

            int lenTwoLimit = Math.min(niceLength, avail - len - 1);
            int lenTwo = lz.getMatchLength(len + 1, opts[optCur].reps[rep], lenTwoLimit);

            if (lenTwo >= MATCH_LEN_MIN) {
                // Rep
                int price = longRepPrice + repLengthEncoder.getPrice(len, posState);
                nextState.set(opts[optCur].state);
                nextState.updateLongRep();

                // Literal
                int curByte = lz.getByte(len, 0);
                int matchByte = lz.getByte(0, 0);
                int prevByte = lz.getByte(len, 1);
                price += literalEncoder.getPrice(curByte, matchByte, prevByte, pos + len, nextState);
                nextState.updateLiteral();

                // Rep0
                int nextPosState = (pos + len + 1) & posMask;
                price += getLongRepAndLenPrice(0, lenTwo, nextState, nextPosState);

                int i = optCur + len + 1 + lenTwo;

                while (optEnd < i)
                    opts[++optEnd].reset();

                if (price < opts[i].price)
                    opts[i].set3(price, optCur, rep, len, 0);
            }
        }

        return startLen;
    }

    /** Calculates prices of a normal match and normal match + literal + rep0. */
    private void calcNormalMatchPrices(int pos, int posState, int avail, int anyMatchPrice, int startLen) {
        // If the longest match is so long that it would not fit into the opts array, shorten the matches.
        if (matches.getLen()[matches.getCount() - 1] > avail) {
            matches.setCount(0);

            while (matches.getLen()[matches.getCount()] < avail)
                matches.incCount();

            matches.getLen()[matches.getCount()] = avail;
            matches.incCount();
        }

        if (matches.getLen()[matches.getCount() - 1] < startLen)
            return;

        while (optEnd < optCur + matches.getLen()[matches.getCount() - 1])
            opts[++optEnd].reset();

        int normalMatchPrice = getNormalMatchPrice(anyMatchPrice, opts[optCur].state);

        int match = 0;

        while (startLen > matches.getLen()[match])
            match++;

        for (int len = startLen; ; len++) {
            int dist = matches.getDist()[match];

            // Calculate the price of a match of len bytes from the nearest possible distance.
            int matchAndLenPrice = getMatchAndLenPrice(normalMatchPrice, dist, len, posState);
            if (matchAndLenPrice < opts[optCur + len].price)
                opts[optCur + len].set1(matchAndLenPrice, optCur, dist + reps.length);

            if (len != matches.getLen()[match])
                continue;

            // Try match + literal + rep0. First get the length of the rep0.
            int lenTwoLimit = Math.min(niceLength, avail - len - 1);
            int lenTwo = lz.getMatchLength(len + 1, dist, lenTwoLimit);

            if (lenTwo >= MATCH_LEN_MIN) {
                nextState.set(opts[optCur].state);
                nextState.updateMatch();

                // Literal
                int curByte = lz.getByte(len, 0);
                int matchByte = lz.getByte(0, 0);
                int prevByte = lz.getByte(len, 1);
                int price = matchAndLenPrice + literalEncoder.getPrice(curByte, matchByte, prevByte, pos + len, nextState);
                nextState.updateLiteral();

                // Rep0
                int nextPosState = (pos + len + 1) & posMask;
                price += getLongRepAndLenPrice(0, lenTwo, nextState, nextPosState);

                int i = optCur + len + 1 + lenTwo;
                while (optEnd < i)
                    opts[++optEnd].reset();

                if (price < opts[i].price)
                    opts[i].set3(price, optCur, dist + reps.length, len, 0);
            }

            if (++match == matches.getCount())
                break;
        }
    }

    private int getNormalMatchPrice(int anyMatchPrice, State state) {
        return anyMatchPrice + rangeEncoder.getBitPrice(isRep[state.get()], 0);
    }

    private int getMatchAndLenPrice(int normalMatchPrice, int dist, int len, int posState) {
        int price = normalMatchPrice + matchLengthEncoder.getPrice(len, posState);
        int distState = getDistState(len);

        if (dist < FULL_DISTANCES)
            price += fullDistPrices[distState][dist];
        else {
            // Note that distSlotPrices includes also the price of direct bits.
            int distSlot = getDistSlot(dist);
            price += distSlotPrices[distState][distSlot] + alignPrices[dist & ALIGN_MASK];
        }

        return price;
    }

    private static final class Optimum {

        private static final int INFINITY_PRICE = 1 << 30;

        private final State state = new State();
        private final int[] reps = new int[4];

        /** Cumulative price of arriving to this byte. */
        private int price;

        private int optPrev;
        private int backPrev;
        private boolean prev1IsLiteral;

        private boolean hasPrev2;
        private int optPrev2;
        private int backPrev2;

        public void reset() {
            price = INFINITY_PRICE;
        }

        public void set1(int newPrice, int optCur, int back) {
            price = newPrice;
            optPrev = optCur;
            backPrev = back;
            prev1IsLiteral = false;
        }

        /** Sets to indicate two LZMA symbols of which the first one is a literal. */
        public void set2(int newPrice, int optCur, int back) {
            price = newPrice;
            optPrev = optCur + 1;
            backPrev = back;
            prev1IsLiteral = true;
            hasPrev2 = false;
        }

        /** Sets to indicate three LZMA symbols of which the second one is a literal. */
        public void set3(int newPrice, int optCur, int back2, int len2, int back) {
            price = newPrice;
            optPrev = optCur + len2 + 1;
            backPrev = back;
            prev1IsLiteral = true;
            hasPrev2 = true;
            optPrev2 = optCur;
            backPrev2 = back2;
        }
    }
}
