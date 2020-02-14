package ru.olegcherednik.zip4jvm.io.readers.os;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.os.ExtendedTimestampExtraFieldRecord;
import ru.olegcherednik.zip4jvm.utils.function.Reader;
import ru.olegcherednik.zip4jvm.utils.time.UnixTimestampConverter;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 25.10.2019
 */
@RequiredArgsConstructor
public final class ExtendedTimestampExtraFieldReader implements Reader<ExtendedTimestampExtraFieldRecord> {

    private final int size;

    @Override
    public ExtendedTimestampExtraFieldRecord read(DataInput in) throws IOException {
        ExtendedTimestampExtraFieldRecord.Flag flag = new ExtendedTimestampExtraFieldRecord.Flag(in.readByte());
        long lastModificationTime = -1;
        long lastAccessTime = -1;
        long creationTime = -1;

        if (flag.isLastModificationTime())
            lastModificationTime = UnixTimestampConverter.unixToJavaTime(in.readDword());
        if (flag.isLastAccessTime())
            lastAccessTime = UnixTimestampConverter.unixToJavaTime(in.readDword());
        if (flag.isCreationTime())
            creationTime = UnixTimestampConverter.unixToJavaTime(in.readDword());

        return ExtendedTimestampExtraFieldRecord.builder()
                                                .dataSize(size)
                                                .flag(flag)
                                                .lastModificationTime(lastModificationTime)
                                                .lastAccessTime(lastAccessTime)
                                                .creationTime(creationTime).build();
    }

}
