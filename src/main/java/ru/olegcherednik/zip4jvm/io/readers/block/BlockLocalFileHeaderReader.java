package ru.olegcherednik.zip4jvm.io.readers.block;

import lombok.Getter;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.readers.ExtraFieldReader;
import ru.olegcherednik.zip4jvm.io.readers.LocalFileHeaderReader;
import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.model.LocalFileHeader;
import ru.olegcherednik.zip4jvm.model.block.ZipEntryBlock;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 20.10.2019
 */
@Getter
public class BlockLocalFileHeaderReader extends LocalFileHeaderReader {

    private final ZipEntryBlock.LocalFileHeaderBlock block = new ZipEntryBlock.LocalFileHeaderBlock();
    private final long disk;

    public BlockLocalFileHeaderReader(ZipEntry zipEntry, Function<Charset, Charset> customizeCharset) {
        super(zipEntry.getLocalFileHeaderOffs(), customizeCharset);
        disk = zipEntry.getDisk();
    }

    @Override
    protected LocalFileHeader readLocalFileHeader(DataInput in) throws IOException {
        return block.getContent().calc(in, () -> super.readLocalFileHeader(in));
    }

    @Override
    protected ExtraField readExtraFiled(int size, LocalFileHeader localFileHeader, DataInput in) throws IOException {
        block.getContent().calc(in.getOffs());
        return new BlockExtraFieldReader(size, ExtraFieldReader.getReaders(localFileHeader), block.getExtraFieldBlock()).read(in);
    }

}
