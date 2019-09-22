package ru.olegcherednik.zip4jvm.crypto.pkware;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.Decoder;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 22.03.2019
 */
@RequiredArgsConstructor
public final class PkwareDecoder implements Decoder {

    private final PkwareEngine engine;

    public static PkwareDecoder create(@NonNull ZipEntry zipEntry, @NonNull DataInput in) throws IOException {
        PkwareEngine engine = new PkwareEngine(zipEntry.getPassword());
        PkwareHeader.read(engine, zipEntry, in);
        return new PkwareDecoder(engine);
    }

    @Override
    public void decrypt(@NonNull byte[] buf, int offs, int len) {
        engine.decrypt(buf, offs, len);
    }

    @Override
    public long getCompressedSize(@NonNull ZipEntry zipEntry) {
        return zipEntry.getCompressedSize() - PkwareHeader.SIZE;
    }

}
