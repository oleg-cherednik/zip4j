package ru.olegcherednik.zip4jvm.model.entry;

import lombok.Getter;
import lombok.Setter;
import ru.olegcherednik.zip4jvm.crypto.Decoder;
import ru.olegcherednik.zip4jvm.crypto.Encoder;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.CompressionLevel;
import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.model.Encryption;
import ru.olegcherednik.zip4jvm.model.ExternalFileAttributes;
import ru.olegcherednik.zip4jvm.utils.function.ZipEntryInputStreamSupplier;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 26.07.2019
 */
@Getter
@Setter
public final class RegularFileZipEntry extends ZipEntry {

    private long checksum;

    public RegularFileZipEntry(String fileName, int lastModifiedTime, ExternalFileAttributes externalFileAttributes,
            CompressionMethod compressionMethod, CompressionLevel compressionLevel, Encryption encryption,
            ZipEntryInputStreamSupplier inputStreamSup) {
        super(fileName, lastModifiedTime, externalFileAttributes, compressionMethod, compressionLevel, encryption, inputStreamSup);
    }

    @Override
    public boolean isRegularFile() {
        return true;
    }

    @Override
    public Decoder createDecoder(DataInput in) throws IOException {
        return encryption.createDecoder(this, in);
    }

    @Override
    public Encoder createEncoder() {
        return encryption.createEncoder(this);
    }

}
