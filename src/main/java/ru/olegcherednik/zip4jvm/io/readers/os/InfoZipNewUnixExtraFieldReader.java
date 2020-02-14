package ru.olegcherednik.zip4jvm.io.readers.os;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.os.InfoZipNewUnixExtraFieldRecord;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 25.10.2019
 */
@RequiredArgsConstructor
public final class InfoZipNewUnixExtraFieldReader implements Reader<InfoZipNewUnixExtraFieldRecord> {

    private final int size;

    @Override
    public InfoZipNewUnixExtraFieldRecord read(DataInput in) throws IOException {
        int version = in.readByte();

        InfoZipNewUnixExtraFieldRecord.Payload payload = version == 1 ? readVersionOnePayload(in) : readVersionUnknown(version, in);

        return InfoZipNewUnixExtraFieldRecord.builder()
                                             .dataSize(size)
                                             .payload(payload).build();
    }

    private static InfoZipNewUnixExtraFieldRecord.VersionOnePayload readVersionOnePayload(DataInput in) throws IOException {
        String uid = in.readNumber(in.readByte(), 16);
        String gid = in.readNumber(in.readByte(), 16);

        return InfoZipNewUnixExtraFieldRecord.VersionOnePayload.builder()
                                                               .uid(uid)
                                                               .gid(gid).build();
    }

    private InfoZipNewUnixExtraFieldRecord.VersionUnknownPayload readVersionUnknown(int version, DataInput in) throws IOException {
        byte[] data = in.readBytes(size - in.byteSize());
        return InfoZipNewUnixExtraFieldRecord.VersionUnknownPayload.builder()
                                                                   .version(version)
                                                                   .data(data).build();
    }
}
