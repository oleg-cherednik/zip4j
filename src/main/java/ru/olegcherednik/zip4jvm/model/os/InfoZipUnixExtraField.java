package ru.olegcherednik.zip4jvm.model.os;

import lombok.Builder;
import lombok.Getter;
import org.apache.commons.lang.NotImplementedException;
import ru.olegcherednik.zip4jvm.io.out.DataOutput;
import ru.olegcherednik.zip4jvm.model.ExtraField;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 25.10.2019
 */
@Getter
@Builder
public final class InfoZipUnixExtraField implements ExtraField.Record {

    public static final InfoZipUnixExtraField NULL = builder().build();

    public static final int SIGNATURE = 0x5855;
    public static final int SIZE_FIELD = 2 + 2; // 4 bytes: signature + size

    // size:2 - attribute tag value #1 (0x5855)
    // size:2 - total data size for this block
    private final int dataSize;
    // size:4 - file last access time
    private final long lastAccessTime;
    // size:4 - file last modification time
    private final long lastModificationTime;
    // size:2 - unix user ID (optional, LocalFileHeader only)
    private final int uid;
    // size:2 - unix group ID (optional, LocalFileHeader only)
    private final int gid;

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

}
