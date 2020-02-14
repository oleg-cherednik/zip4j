package ru.olegcherednik.zip4jvm.io.lzma.lz;

import ru.olegcherednik.zip4jvm.io.lzma.LzmaInputStream;

import static ru.olegcherednik.zip4jvm.io.lzma.LzmaEncoder.MATCH_LEN_MAX;

/**
 * @author Oleg Cherednik
 * @since 14.02.2020
 */
final class HashChain extends LzEncoder {

    private final CRC32Hash hash;
    private final int[] chain;
    private final Matches matches;
    private final int depthLimit;
    private final int niceLength;
    private final int cyclicSize;

    private int cyclicPos = -1;
    private int lzPos;

    /**
     * Creates a new LZEncoder with the HC4 match finder.<br>
     * See <code>LZEncoder.getInstance</code> for parameter descriptions.
     */
    public HashChain(LzmaInputStream.Properties properties, int extraSizeAfter) {
        super(properties, extraSizeAfter);

        niceLength = properties.getNiceLength();
        hash = new CRC32Hash(properties.getDictionarySize());

        // +1 because we need dictSize bytes of history + the current byte.
        cyclicSize = properties.getDictionarySize() + 1;
        chain = new int[cyclicSize];
        lzPos = cyclicSize;

        /*
         * Substracting 1 because the shortest match that this match finder can find is 2 bytes, so there's no need to reserve space for one-byte
         * matches.
         */
        matches = new Matches(properties.getNiceLength() - 1);

        /*
         * Use a default depth limit if no other value was specified.
         * The default is just something based on experimentation; it's nothing magic.
         */
        depthLimit = properties.getDepthLimit() > 0 ? properties.getDepthLimit() : 4 + properties.getNiceLength() / 4;
    }

    @Override
    public Matches getMatches() {
        matches.setCount(0);
        int matchLenLimit = MATCH_LEN_MAX;
        int niceLenLimit = niceLength;
        int avail = movePos();

        if (avail < matchLenLimit) {
            if (avail == 0)
                return matches;

            matchLenLimit = avail;

            if (niceLenLimit > avail)
                niceLenLimit = avail;
        }

        hash.calcHashes(buf, pos);
        int delta2 = lzPos - hash.getHash2Pos();
        int delta3 = lzPos - hash.getHash3Pos();
        int currentMatch = hash.getHash4Pos();
        hash.updateTables(lzPos);

        chain[cyclicPos] = currentMatch;

        int lenBest = 0;

        /*
         * See if the hash from the first two bytes found a match.
         * The hashing algorithm guarantees that if the first byte matches, also the second byte does, so there's no need to test the second byte.
         */
        if (delta2 < cyclicSize && buf[pos - delta2] == buf[pos]) {
            lenBest = 2;
            matches.getLen()[0] = 2;
            matches.getDist()[0] = delta2 - 1;
            matches.setCount(1);
        }

        /*
         * See if the hash from the first three bytes found a match that is different from the match possibly found by the two-byte hash.
         * Also here the hashing algorithm guarantees that if the first byte matches, also the next two bytes do.
         */
        if (delta2 != delta3 && delta3 < cyclicSize && buf[pos - delta3] == buf[pos]) {
            lenBest = 3;
            matches.getDist()[matches.getCount()] = delta3 - 1;
            matches.incCount();
            delta2 = delta3;
        }

        // If a match was found, see how long it is.
        if (matches.getCount() > 0) {
            while (lenBest < matchLenLimit && buf[pos + lenBest - delta2] == buf[pos + lenBest])
                ++lenBest;

            matches.getLen()[matches.getCount() - 1] = lenBest;

            // Return if it is long enough (niceLen or reached the end of the dictionary).
            if (lenBest >= niceLenLimit)
                return matches;
        }

        // Long enough match wasn't found so easily. Look for better matches from the hash chain.
        if (lenBest < 3)
            lenBest = 3;

        int depth = depthLimit;

        while (true) {
            int delta = lzPos - currentMatch;

            // Return if the search depth limit has been reached or if the distance of the potential match exceeds the dictionary size.
            if (depth-- == 0 || delta >= cyclicSize)
                return matches;

            currentMatch = chain[cyclicPos - delta + (delta > cyclicPos ? cyclicSize : 0)];

            /*
             * Test the first byte and the first new byte that would give us a match that is at least one byte longer than lenBest. This too short
             * matches get quickly skipped.
             */
            if (buf[pos + lenBest - delta] == buf[pos + lenBest] && buf[pos - delta] == buf[pos]) {
                // Calculate the length of the match.
                int len = 0;
                while (++len < matchLenLimit)
                    if (buf[pos + len - delta] != buf[pos + len])
                        break;

                // Use the match if and only if it is better than the longest match found so far.
                if (len > lenBest) {
                    lenBest = len;
                    matches.getLen()[matches.getCount()] = len;
                    matches.getDist()[matches.getCount()] = delta - 1;
                    matches.incCount();

                    // Return if it is long enough (niceLen or reached the end of the dictionary).
                    if (len >= niceLenLimit)
                        return matches;
                }
            }
        }
    }

    @Override
    public void skip(int len) {
        while (len-- > 0) {
            if (movePos() != 0) {
                // Update the hash chain and hash tables.
                hash.calcHashes(buf, pos);
                chain[cyclicPos] = hash.getHash4Pos();
                hash.updateTables(lzPos);
            }
        }
    }

    /**
     * Moves to the next byte, checks that there is enough available space,
     * and possibly normalizes the hash tables and the hash chain.
     *
     * @return number of bytes available, including the current byte
     */
    private int movePos() {
        int avail = movePos(4, 4);

        if (avail != 0) {
            if (++lzPos == Integer.MAX_VALUE) {
                int normalizationOffset = Integer.MAX_VALUE - cyclicSize;
                hash.normalize(normalizationOffset);
                normalize(chain, cyclicSize, normalizationOffset);
                lzPos -= normalizationOffset;
            }

            if (++cyclicPos == cyclicSize)
                cyclicPos = 0;
        }

        return avail;
    }
}
