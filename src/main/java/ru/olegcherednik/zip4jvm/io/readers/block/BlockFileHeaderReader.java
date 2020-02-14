package ru.olegcherednik.zip4jvm.io.readers.block;

import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.readers.ExtraFieldReader;
import ru.olegcherednik.zip4jvm.io.readers.FileHeaderReader;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.model.block.CentralDirectoryBlock;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 20.10.2019
 */
public class BlockFileHeaderReader extends FileHeaderReader {

    private final CentralDirectoryBlock centralDirectoryBlock;
    private CentralDirectoryBlock.FileHeaderBlock block;

    public BlockFileHeaderReader(long totalEntries, Function<Charset, Charset> charsetCustomizer, CentralDirectoryBlock centralDirectoryBlock) {
        super(totalEntries, charsetCustomizer);
        this.centralDirectoryBlock = centralDirectoryBlock;
    }

    @Override
    protected CentralDirectory.FileHeader readFileHeader(DataInput in) throws IOException {
        block = new CentralDirectoryBlock.FileHeaderBlock();
        CentralDirectory.FileHeader fileHeader = block.calc(in, () -> super.readFileHeader(in));
        centralDirectoryBlock.addFileHeader(fileHeader.getFileName(), block);
        return fileHeader;
    }

    @Override
    protected ExtraFieldReader getExtraFiledReader(int size, CentralDirectory.FileHeader fileHeader) {
        return new BlockExtraFieldReader(size, ExtraFieldReader.getReaders(fileHeader), block.getExtraFieldBlock());
    }

}
