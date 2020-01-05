package ru.olegcherednik.zip4jvm.crypto.strong;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.Decoder;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 09.10.2019
 */
@RequiredArgsConstructor
public final class StrongDecoder implements Decoder {

    public static StrongDecoder create(ZipEntry zipEntry, DataInput in) throws IOException {
//        PkwareEngine engine = new PkwareEngine(zipEntry.getPassword());
//        PkwareHeader.read(engine, zipEntry, in);
        return new StrongDecoder(/*engine*/);
    }

    @Override
    public void decrypt(byte[] buf, int offs, int len) {

    }

    @Override
    public long getDataCompressedSize(long compressedSize) {
        return 0;
    }

    public long getCompressedSize(ZipEntry zipEntry) {
        return 0;
    }
}
