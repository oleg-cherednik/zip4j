package ru.olegcherednik.zip4jvm.io.readers.os;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.os.InfoZipOldUnixExtraFieldRecord;
import ru.olegcherednik.zip4jvm.utils.function.Reader;
import ru.olegcherednik.zip4jvm.utils.time.UnixTimestampConverter;

import java.io.IOException;

import static ru.olegcherednik.zip4jvm.model.ExtraField.NO_DATA;

/**
 * @author Oleg Cherednik
 * @since 25.10.2019
 */
@RequiredArgsConstructor
public final class InfoZipOldUnitExtraFieldReader implements Reader<InfoZipOldUnixExtraFieldRecord> {

    private final int size;

    @Override
    public InfoZipOldUnixExtraFieldRecord read(DataInput in) throws IOException {
        long lastAccessTime = UnixTimestampConverter.unixToJavaTime(in.readDword());
        long lastModificationTime = UnixTimestampConverter.unixToJavaTime(in.readDword());
        int uid = size >= 10 ? in.readWord() : NO_DATA;
        int gid = size >= 12 ? in.readWord() : NO_DATA;

        return InfoZipOldUnixExtraFieldRecord.builder()
                                             .dataSize(size)
                                             .lastAccessTime(lastAccessTime)
                                             .lastModificationTime(lastModificationTime)
                                             .uid(uid)
                                             .gid(gid).build();
    }

}
