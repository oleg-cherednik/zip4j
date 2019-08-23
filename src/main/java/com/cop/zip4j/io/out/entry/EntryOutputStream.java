package com.cop.zip4j.io.out.entry;

import com.cop.zip4j.crypto.Encoder;
import com.cop.zip4j.exception.Zip4jException;
import com.cop.zip4j.io.out.DataOutput;
import com.cop.zip4j.io.writers.DataDescriptorWriter;
import com.cop.zip4j.io.writers.LocalFileHeaderWriter;
import com.cop.zip4j.model.CentralDirectory;
import com.cop.zip4j.model.Compression;
import com.cop.zip4j.model.DataDescriptor;
import com.cop.zip4j.model.LocalFileHeader;
import com.cop.zip4j.model.ZipModel;
import com.cop.zip4j.model.builders.CentralDirectoryBuilder;
import com.cop.zip4j.model.builders.LocalFileHeaderBuilder;
import com.cop.zip4j.model.entry.PathZipEntry;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

/**
 * @author Oleg Cherednik
 * @since 26.07.2019
 */
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class EntryOutputStream extends OutputStream {

    public static final int SPLIT_SIGNATURE = 0x08074b50;

    private static final String MARK = EntryOutputStream.class.getSimpleName();

    private final ZipModel zipModel;
    private final CentralDirectory.FileHeader fileHeader;
    private final Checksum checksum = new CRC32();

    protected final Encoder encoder;
    protected final DataOutput out;

    public static EntryOutputStream create(@NonNull PathZipEntry entry, @NonNull ZipModel zipModel, @NonNull DataOutput out) throws IOException {
        return createOutputStream(entry, zipModel, out).writeHeader();
    }

    private static EntryOutputStream createOutputStream(PathZipEntry entry, ZipModel zipModel, DataOutput out) throws IOException {
        Compression compression = entry.getCompression();
        Encoder encoder = entry.getEncryption().getCreateEncoder().apply(entry);
        CentralDirectory.FileHeader fileHeader = new CentralDirectoryBuilder(entry, zipModel, out.getCounter()).create();

        if (compression == Compression.STORE)
            return new StoreEntryOutputStream(zipModel, fileHeader, encoder, out);
        if (compression == Compression.DEFLATE)
            return new DeflateEntryOutputStream(zipModel, fileHeader, encoder, out, entry.getCompressionLevel());

        throw new Zip4jException("Compression is not supported: " + compression);
    }

    private EntryOutputStream writeHeader() throws IOException {
        // only at the beginning of the split file
        if (zipModel.isSplitArchive() && zipModel.isEmpty())
            out.writeDwordSignature(SPLIT_SIGNATURE);

        zipModel.addFileHeader(fileHeader);
        writeLocalFileHeader();
        encoder.writeHeader(out);

        return this;
    }

    private void writeLocalFileHeader() throws IOException {
        // TODO is this always 0?
        fileHeader.setOffsLocalFileHeader(out.getOffs());
        LocalFileHeader localFileHeader = new LocalFileHeaderBuilder(zipModel, fileHeader).create();
        new LocalFileHeaderWriter(localFileHeader, zipModel.getCharset()).write(out);
        out.mark(MARK);
    }

    protected final void updateChecksum(byte[] buf, int offs, int len) {
        checksum.update(buf, offs, len);
    }

    @Override
    public final void write(int b) throws IOException {
        write(new byte[] { (byte)b }, 0, 1);
    }

    @Override
    public void close() throws IOException {
        encoder.close(out);

        checkChecksum();
        checkCompressedSize();

        updateFileHeader();
        writeDataDescriptor();
    }

    private void checkChecksum() {
        long expected = fileHeader.getCrc32();
        long actual = checksum.getValue();

        if (expected != 0 && expected != actual)
            throw new Zip4jException("Checksum is not matched: " + fileHeader.getFileName());
    }

    private void checkCompressedSize() {
        long expected = fileHeader.getCompressedSize();
        long actual = out.getWrittenBytesAmount(MARK);

        if (expected != 0 && expected != actual)
            throw new Zip4jException("CompressedSize is not matched: " + fileHeader.getFileName());
    }

    private void updateFileHeader() {
        fileHeader.setCrc32(fileHeader.getEncryption().getChecksum().apply(fileHeader));
        fileHeader.setCompressedSize(out.getWrittenBytesAmount(MARK));
    }

    private void writeDataDescriptor() throws IOException {
        // TODO avoid add it for folders
        if (fileHeader.getGeneralPurposeFlag().isDataDescriptorExists()) {
            DataDescriptor dataDescriptor = new DataDescriptor();
            dataDescriptor.setCrc32(checksum.getValue());
            dataDescriptor.setCompressedSize(fileHeader.getCompressedSize());
            dataDescriptor.setUncompressedSize(fileHeader.getUncompressedSize());

            new DataDescriptorWriter(dataDescriptor, zipModel.isZip64()).write(out);
        }
    }

}
