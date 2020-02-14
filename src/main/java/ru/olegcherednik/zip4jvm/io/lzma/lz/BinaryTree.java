package ru.olegcherednik.zip4jvm.io.lzma.lz;

import ru.olegcherednik.zip4jvm.io.lzma.LzmaInputStream;

import static ru.olegcherednik.zip4jvm.io.lzma.LzmaEncoder.MATCH_LEN_MAX;

/**
 * @author Oleg Cherednik
 * @since 14.02.2020
 */
final class BinaryTree extends LzEncoder {

    private final CRC32Hash hash;
    private final int[] tree;
    private final Matches matches;
    private final int depthLimit;

    private final int niceLength;
    private final int cyclicSize;
    private int cyclicPos = -1;
    private int lzPos;

    public BinaryTree(LzmaInputStream.Properties properties, int extraSizeAfter) {
        super(properties, extraSizeAfter);
        niceLength = properties.getNiceLength();
        cyclicSize = properties.getDictionarySize() + 1;
        lzPos = cyclicSize;

        hash = new CRC32Hash(properties.getDictionarySize());
        tree = new int[cyclicSize * 2];

        /*
         * Substracting 1 because the shortest match that this match finder can find is 2 bytes, so there's no need to reserve space for one-byte
         * matches.
         */
        matches = new Matches(niceLength - 1);
        depthLimit = properties.getDepthLimit() > 0 ? properties.getDepthLimit() : 16 + niceLength / 2;
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
        int deltaTwo = lzPos - hash.getHash2Pos();
        int delta3 = lzPos - hash.getHash3Pos();
        int currentMatch = hash.getHash4Pos();

        hash.updateTables(lzPos);

        int lenBest = 0;

        /*
         * See if the hash from the first two bytes found a match.
         * The hashing algorithm guarantees that if the first byte matches, also the second byte does, so there's no need to test the second byte.
         */
        if (deltaTwo < cyclicSize && buf[pos - deltaTwo] == buf[pos]) {
            lenBest = 2;
            matches.getLen()[0] = 2;
            matches.getDist()[0] = deltaTwo - 1;
            matches.setCount(1);
        }

        /*
         * See if the hash from the first three bytes found a match that is different from the match possibly found by the two-byte hash.
         * Also here the hashing algorithm guarantees that if the first byte matches, also the next two bytes do.
         */
        if (deltaTwo != delta3 && delta3 < cyclicSize && buf[pos - delta3] == buf[pos]) {
            lenBest = 3;
            matches.getDist()[matches.getCount()] = delta3 - 1;
            matches.incCount();
            deltaTwo = delta3;
        }

        // If a match was found, see how long it is.
        if (matches.getCount() > 0) {
            while (lenBest < matchLenLimit && buf[pos + lenBest - deltaTwo] == buf[pos + lenBest])
                ++lenBest;

            matches.getLen()[matches.getCount() - 1] = lenBest;

            // Return if it is long enough (niceLen or reached the end of the dictionary).
            if (lenBest >= niceLenLimit) {
                skip(niceLenLimit, currentMatch);
                return matches;
            }
        }

        // Long enough match wasn't found so easily. Look for better matches from the binary tree.
        if (lenBest < 3)
            lenBest = 3;

        int depth = depthLimit;

        int ptr0 = (cyclicPos << 1) + 1;
        int ptr1 = cyclicPos << 1;
        int len0 = 0;
        int len1 = 0;

        while (true) {
            int delta = lzPos - currentMatch;

            // Return if the search depth limit has been reached or if the distance of the potential match exceeds the dictionary size.
            if (depth-- == 0 || delta >= cyclicSize) {
                tree[ptr0] = 0;
                tree[ptr1] = 0;
                return matches;
            }

            int pair = (cyclicPos - delta + (delta > cyclicPos ? cyclicSize : 0)) << 1;
            int len = Math.min(len0, len1);

            if (buf[pos + len - delta] == buf[pos + len]) {
                while (++len < matchLenLimit)
                    if (buf[pos + len - delta] != buf[pos + len])
                        break;

                if (len > lenBest) {
                    lenBest = len;
                    matches.getLen()[matches.getCount()] = len;
                    matches.getDist()[matches.getCount()] = delta - 1;
                    matches.incCount();

                    if (len >= niceLenLimit) {
                        tree[ptr1] = tree[pair];
                        tree[ptr0] = tree[pair + 1];
                        return matches;
                    }
                }
            }

            if ((buf[pos + len - delta] & 0xFF) < (buf[pos + len] & 0xFF)) {
                tree[ptr1] = currentMatch;
                ptr1 = pair + 1;
                currentMatch = tree[ptr1];
                len1 = len;
            } else {
                tree[ptr0] = currentMatch;
                ptr0 = pair;
                currentMatch = tree[ptr0];
                len0 = len;
            }
        }
    }

    @Override
    public void skip(int len) {
        while (len-- > 0) {
            int niceLenLimit = niceLength;
            int avail = movePos();

            if (avail < niceLenLimit) {
                if (avail == 0)
                    continue;

                niceLenLimit = avail;
            }

            hash.calcHashes(buf, pos);
            int currentMatch = hash.getHash4Pos();
            hash.updateTables(lzPos);
            skip(niceLenLimit, currentMatch);
        }
    }

    private void skip(int niceLengthLimit, int currentMatch) {
        int depth = depthLimit;

        int ptr0 = (cyclicPos << 1) + 1;
        int ptr1 = cyclicPos << 1;
        int len0 = 0;
        int len1 = 0;

        while (true) {
            int delta = lzPos - currentMatch;

            if (depth-- == 0 || delta >= cyclicSize) {
                tree[ptr0] = 0;
                tree[ptr1] = 0;
                return;
            }

            int pair = (cyclicPos - delta + (delta > cyclicPos ? cyclicSize : 0)) << 1;
            int len = Math.min(len0, len1);

            if (buf[pos + len - delta] == buf[pos + len]) {
                /*
                 * No need to look for longer matches than niceLenLimit because we only are updating the tree, not returning matches found to the
                 * caller.
                 */
                do {
                    if (++len == niceLengthLimit) {
                        tree[ptr1] = tree[pair];
                        tree[ptr0] = tree[pair + 1];
                        return;
                    }
                } while (buf[pos + len - delta] == buf[pos + len]);
            }

            if ((buf[pos + len - delta] & 0xFF) < (buf[pos + len] & 0xFF)) {
                tree[ptr1] = currentMatch;
                ptr1 = pair + 1;
                currentMatch = tree[ptr1];
                len1 = len;
            } else {
                tree[ptr0] = currentMatch;
                ptr0 = pair;
                currentMatch = tree[ptr0];
                len0 = len;
            }
        }
    }

    private int movePos() {
        int avail = movePos(niceLength, 4);

        if (avail != 0) {
            if (++lzPos == Integer.MAX_VALUE) {
                int normalizationOffset = Integer.MAX_VALUE - cyclicSize;
                hash.normalize(normalizationOffset);
                normalize(tree, cyclicSize * 2, normalizationOffset);
                lzPos -= normalizationOffset;
            }

            if (++cyclicPos == cyclicSize)
                cyclicPos = 0;
        }

        return avail;
    }
}
