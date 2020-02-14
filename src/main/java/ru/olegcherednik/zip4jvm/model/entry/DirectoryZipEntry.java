package ru.olegcherednik.zip4jvm.model.entry;

import ru.olegcherednik.zip4jvm.model.CompressionLevel;
import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.model.Encryption;
import ru.olegcherednik.zip4jvm.model.ExternalFileAttributes;
import ru.olegcherednik.zip4jvm.utils.EmptyInputStreamSupplier;

/**
 * @author Oleg Cherednik
 * @since 26.07.2019
 */
final class DirectoryZipEntry extends ZipEntry {

    public DirectoryZipEntry(String fileName, int lastModifiedTime, ExternalFileAttributes externalFileAttributes) {
        super(fileName, lastModifiedTime, externalFileAttributes, CompressionMethod.STORE, CompressionLevel.NORMAL, Encryption.OFF,
                EmptyInputStreamSupplier.INSTANCE);
    }

    @Override
    public boolean isDirectory() {
        return true;
    }

    @Override
    public void setCompressedSize(long compressedSize) {
        /* nothing to set */
    }

}
