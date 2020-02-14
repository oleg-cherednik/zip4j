package ru.olegcherednik.zip4jvm.crypto.pkware;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.Encoder;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;

import static ru.olegcherednik.zip4jvm.utils.ValidationUtils.requireNotEmpty;

/**
 * @author Oleg Cherednik
 * @since 22.03.2019
 */
@RequiredArgsConstructor
public final class PkwareEncoder implements Encoder {

    private final PkwareEngine engine;
    private final PkwareHeader header;

    public static PkwareEncoder create(ZipEntry entry) {
        requireNotEmpty(entry.getPassword(), entry.getFileName() + ".password");

        PkwareEngine engine = new PkwareEngine(entry.getPassword());
        PkwareHeader header = PkwareHeader.create(engine, entry.getLastModifiedTime());
        return new PkwareEncoder(engine, header);
    }

    @Override
    public void writeEncryptionHeader(DataOutput out) throws IOException {
        header.write(out);
    }

    @Override
    public void encrypt(byte[] buf, int offs, int len) {
        engine.encrypt(buf, offs, len);
    }

}
