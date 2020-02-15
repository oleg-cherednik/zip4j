package ru.olegcherednik.zip4jvm.crypto.strong;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.Encoder;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 09.10.2019
 */
@RequiredArgsConstructor
public final class StrongEncoder implements Encoder {

    public static StrongEncoder create(ZipEntry entry) {
//        PkwareEngine engine = new PkwareEngine(entry.getPassword());
//        PkwareHeader header = PkwareHeader.create(engine, entry.getLastModifiedTime());
        return new StrongEncoder(/*engine, header*/);
    }

    @Override
    public void writeEncryptionHeader(DataOutput out) throws IOException {

    }

    @Override
    public void encrypt(byte[] buf, int offs, int len) {

    }
}
