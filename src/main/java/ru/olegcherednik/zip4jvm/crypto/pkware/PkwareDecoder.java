package ru.olegcherednik.zip4jvm.crypto.pkware;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.Decoder;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;

import static ru.olegcherednik.zip4jvm.utils.ValidationUtils.requireNotEmpty;

/**
 * @author Oleg Cherednik
 * @since 22.03.2019
 */
@RequiredArgsConstructor
public final class PkwareDecoder implements Decoder {

    private final PkwareEngine engine;

    public static PkwareDecoder create(ZipEntry entry, DataInput in) throws IOException {
        requireNotEmpty(entry.getPassword(), entry.getFileName() + ".password");

        PkwareEngine engine = new PkwareEngine(entry.getPassword());
        PkwareHeader.read(engine, entry, in);
        return new PkwareDecoder(engine);
    }

    @Override
    public void decrypt(byte[] buf, int offs, int len) {
        engine.decrypt(buf, offs, len);
    }

    @Override
    public long getDataCompressedSize(long compressedSize) {
        return compressedSize - PkwareHeader.SIZE;
    }

}
