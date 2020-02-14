package ru.olegcherednik.zip4jvm.io.lzma;

import ru.olegcherednik.zip4jvm.io.lzma.lz.LzEncoder;
import ru.olegcherednik.zip4jvm.io.lzma.lz.Matches;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

/**
 * @author Oleg Cherednik
 * @since 14.02.2020
 */
final class LzmaEncoderFast extends LzmaEncoder {

    private final int niceLength;
    private Matches matches;

    public LzmaEncoderFast(DataOutput out, LzmaInputStream.Properties properties) {
        super(out, createEncoder(properties), properties);
        niceLength = properties.getNiceLength();
    }

    private static LzEncoder createEncoder(LzmaInputStream.Properties properties) {
        return properties.getMatchFinder().createEncoder(properties, MATCH_LEN_MAX - 1);
    }

    @Override
    public int getNextSymbol() {
        // Get the matches for the next byte unless readAhead indicates that we already got the new matches during the previous call to this function.
        if (readAhead == -1)
            matches = getMatches();

        back = -1;

        /*
         * Get the number of bytes available in the dictionary, but not more than the maximum match length. If there aren't enough bytes remaining to
         * encode a match at all, return immediately to encode this byte as a literal.
         */
        int avail = Math.min(lz.available(), MATCH_LEN_MAX);
        if (avail < MATCH_LEN_MIN)
            return 1;

        // Look for a match from the previous four match distances.
        int bestRepLen = 0;
        int bestRepIndex = 0;
        for (int rep = 0; rep < reps.length; ++rep) {
            int len = lz.getMatchLength(0, reps[rep], avail);

            if (len < MATCH_LEN_MIN)
                continue;

            // If it is long enough, return it.
            if (len >= niceLength) {
                back = rep;
                skip(len - 1);
                return len;
            }

            // Remember the index and length of the best repeated match.
            if (len > bestRepLen) {
                bestRepIndex = rep;
                bestRepLen = len;
            }
        }

        int mainLen = 0;
        int mainDist = 0;

        if (matches.getCount() > 0) {
            mainLen = matches.getLen()[matches.getCount() - 1];
            mainDist = matches.getDist()[matches.getCount() - 1];

            if (mainLen >= niceLength) {
                back = mainDist + reps.length;
                skip(mainLen - 1);
                return mainLen;
            }

            while (matches.getCount() > 1 && mainLen == matches.getLen()[matches.getCount() - 2] + 1) {
                if (!changePair(matches.getDist()[matches.getCount() - 2], mainDist))
                    break;

                matches.decCount();
                mainLen = matches.getLen()[matches.getCount() - 1];
                mainDist = matches.getDist()[matches.getCount() - 1];
            }

            if (mainLen == MATCH_LEN_MIN && mainDist >= 0x80)
                mainLen = 1;
        }

        if (bestRepLen >= MATCH_LEN_MIN) {
            if (bestRepLen + 1 >= mainLen || (bestRepLen + 2 >= mainLen && mainDist >= (1 << 9))
                    || (bestRepLen + 3 >= mainLen && mainDist >= (1 << 15))) {
                back = bestRepIndex;
                skip(bestRepLen - 1);
                return bestRepLen;
            }
        }

        if (mainLen < MATCH_LEN_MIN || avail <= MATCH_LEN_MIN)
            return 1;

        // Get the next match. Test if it is better than the current match. If so, encode the current byte as a literal.
        matches = getMatches();

        if (matches.getCount() > 0) {
            int newLen = matches.getLen()[matches.getCount() - 1];
            int newDist = matches.getDist()[matches.getCount() - 1];

            if ((newLen >= mainLen && newDist < mainDist) || (newLen == mainLen + 1 && !changePair(mainDist, newDist))
                    || newLen > mainLen + 1 || (newLen + 1 >= mainLen && mainLen >= MATCH_LEN_MIN + 1 && changePair(newDist, mainDist)))
                return 1;
        }

        int limit = Math.max(mainLen - 1, MATCH_LEN_MIN);

        for (int rep = 0; rep < reps.length; ++rep)
            if (lz.getMatchLength(0, reps[rep], limit) == limit)
                return 1;

        back = mainDist + reps.length;
        skip(mainLen - 2);
        return mainLen;
    }

    private static boolean changePair(int smallDist, int bigDist) {
        return smallDist < (bigDist >>> 7);
    }

}
