package ru.olegcherednik.zip4jvm.io.lzma.lz;

import ru.olegcherednik.zip4jvm.io.lzma.LzmaInputStream;

/**
 * @author Oleg Cherednik
 * @since 13.02.2020
 */
public enum MatchFinder {
    HASH_CHAIN {
        @Override
        public LzEncoder createEncoder(LzmaInputStream.Properties properties, int extraSizeAfter) {
            return new HashChain(properties, extraSizeAfter);
        }
    },
    BINARY_TREE {
        @Override
        public LzEncoder createEncoder(LzmaInputStream.Properties properties, int extraSizeAfter) {
            return new BinaryTree(properties, extraSizeAfter);
        }
    };

    public abstract LzEncoder createEncoder(LzmaInputStream.Properties properties, int extraSizeAfter);
}
