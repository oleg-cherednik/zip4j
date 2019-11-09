package ru.olegcherednik.zip4jvm.model.os;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.commons.lang.NotImplementedException;
import ru.olegcherednik.zip4jvm.io.out.DataOutput;
import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.utils.BitUtils;

import java.io.IOException;

import static ru.olegcherednik.zip4jvm.utils.BitUtils.BIT0;
import static ru.olegcherednik.zip4jvm.utils.BitUtils.BIT1;
import static ru.olegcherednik.zip4jvm.utils.BitUtils.BIT2;

/**
 * Added under Ubuntu
 *
 * @author Oleg Cherednik
 * @since 25.10.2019
 */
@Getter
@Builder
public final class ExtendedTimestampExtraField implements ExtraField.Record {

    public static final ExtendedTimestampExtraField NULL = builder().build();

    public static final int SIGNATURE = 0x5455;
    public static final int SIZE_FIELD = 2 + 2; // 4 bytes: signature + size

    // size:2 - attribute tag value #1 (0x5455)
    // size:2 - total data size for this block
    private final int dataSize;
    // size:1 - bit flag
    private final Flag flag;
    // size:4 - file last modification time
    private final long lastModificationTime;
    // size:4 - file last access time
    private final long lastAccessTime;
    // size:4 - file creation time
    private final long creationTime;

    @Override
    public int getSignature() {
        return SIGNATURE;
    }

    @Override
    public int getBlockSize() {
        return this == NULL ? 0 : dataSize + SIZE_FIELD;
    }

    @Override
    public boolean isNull() {
        return this == NULL;
    }

    @Override
    public void write(DataOutput out) throws IOException {
        throw new NotImplementedException();
    }

    @Getter
    @Setter
    @NoArgsConstructor
    public static class Flag {

        private boolean lastModificationTime;
        private boolean lastAccessTime;
        private boolean creationTime;

        public Flag(int data) {
            read(data);
        }

        public void read(int data) {
            lastModificationTime = BitUtils.isBitSet(data, BIT0);
            lastAccessTime = BitUtils.isBitSet(data, BIT1);
            creationTime = BitUtils.isBitSet(data, BIT2);
        }
    }

}