package ru.olegcherednik.zip4jvm.io.lzma;

import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

/**
 * @author Oleg Cherednik
 * @since 13.02.2020
 */
public enum Mode {
    FAST {
        @Override
        public LzmaEncoder createEncoder(DataOutput out, LzmaInputStream.Properties properties) {
            return new LzmaEncoderFast(out, properties);
        }
    },
    NORMAL {
        @Override
        public LzmaEncoder createEncoder(DataOutput out, LzmaInputStream.Properties properties) {
            return new LzmaEncoderNormal(out, properties);
        }
    };

    public abstract LzmaEncoder createEncoder(DataOutput out, LzmaInputStream.Properties properties);
}
