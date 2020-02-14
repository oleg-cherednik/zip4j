package ru.olegcherednik.zip4jvm.io.out.entry;

import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.io.out.data.DecoderDataOutput;
import ru.olegcherednik.zip4jvm.io.out.data.DecoderDataOutputDecorator;
import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 12.02.2020
 */
public abstract class EntryOutputStream extends EntryMetadataOutputStream {

    public static EntryOutputStream create(ZipEntry zipEntry, ZipModel zipModel, DataOutput out) throws IOException {
        EntryOutputStream os = createOutputStream(zipEntry, out);

        // TODO move it to the separate method
        zipModel.addEntry(zipEntry);
        zipEntry.setLocalFileHeaderOffs(out.getOffs());

        os.writeLocalFileHeader();
        os.writeEncryptionHeader();
        return os;
    }

    private static EntryOutputStream createOutputStream(ZipEntry zipEntry, DataOutput out) throws IOException {
        CompressionMethod compressionMethod = zipEntry.getCompressionMethod();
        zipEntry.setDisk(out.getDisk());

        if (compressionMethod == CompressionMethod.STORE)
            return new StoreEntryOutputStream(zipEntry, out);
        if (compressionMethod == CompressionMethod.DEFLATE)
            return new DeflateEntryOutputStream(zipEntry, out);
        if (compressionMethod == CompressionMethod.LZMA)
            return new LzmaEntryOutputStream(zipEntry, out);

        throw new Zip4jvmException("Compression is not supported: " + compressionMethod);
    }

    protected final DecoderDataOutput out;

    protected EntryOutputStream(ZipEntry zipEntry, DataOutput out) {
        super(zipEntry, out);
        this.out = new DecoderDataOutputDecorator(out, zipEntry.createEncoder());
    }

    private void writeEncryptionHeader() throws IOException {
        out.writeEncryptionHeader();
    }

    @Override
    public void close() throws IOException {
        out.encodingAccomplished();
        super.close();
    }
}
