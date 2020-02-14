package ru.olegcherednik.zip4jvm.io.readers.os;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.os.NtfsTimestampExtraFieldRecord;
import ru.olegcherednik.zip4jvm.utils.function.Reader;
import ru.olegcherednik.zip4jvm.utils.time.NtfsTimestampConverter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * @author Oleg Cherednik
 * @since 16.10.2019
 */
@RequiredArgsConstructor
public final class NtfsTimestampExtraFieldReader implements Reader<NtfsTimestampExtraFieldRecord> {

    private final int size;

    @Override
    public NtfsTimestampExtraFieldRecord read(DataInput in) throws IOException {
        long offs = in.getOffs();

        in.skip(4);

        List<NtfsTimestampExtraFieldRecord.Tag> tags = readTags(offs, in);

        return NtfsTimestampExtraFieldRecord.builder()
                                            .dataSize(size)
                                            .tags(tags).build();
    }

    private List<NtfsTimestampExtraFieldRecord.Tag> readTags(long offs, DataInput in) throws IOException {
        List<NtfsTimestampExtraFieldRecord.Tag> tags = new ArrayList<>();

        while (in.getOffs() < offs + size) {
            int tag = in.readWord();
            tags.add(tag == NtfsTimestampExtraFieldRecord.OneTag.SIGNATURE ? readOneTag(in) : readUnknownTag(tag, in));
        }

        return tags.isEmpty() ? Collections.emptyList() : Collections.unmodifiableList(tags);
    }

    private static NtfsTimestampExtraFieldRecord.OneTag readOneTag(DataInput in) throws IOException {
        int size = in.readWord();
        // TODO size should be equal to 8 * 3

        long lastModificationTime = NtfsTimestampConverter.ntfsToJavaTime(in.readQword());
        long lastAccessTime = NtfsTimestampConverter.ntfsToJavaTime(in.readQword());
        long creationTime = NtfsTimestampConverter.ntfsToJavaTime(in.readQword());

        return NtfsTimestampExtraFieldRecord.OneTag.builder()
                                                   .lastModificationTime(lastModificationTime)
                                                   .lastAccessTime(lastAccessTime)
                                                   .creationTime(creationTime).build();
    }

    private static NtfsTimestampExtraFieldRecord.UnknownTag readUnknownTag(int tag, DataInput in) throws IOException {
        int size = in.readWord();
        byte[] data = in.readBytes(size);
        return NtfsTimestampExtraFieldRecord.UnknownTag.builder()
                                                       .signature(tag)
                                                       .data(data).build();
    }

    @Override
    public String toString() {
        return String.format("NTFS Timestamps (0x%04X)", NtfsTimestampExtraFieldRecord.SIGNATURE);
    }

}
