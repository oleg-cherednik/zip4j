package ru.olegcherednik.zip4jvm.io.readers.block;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.readers.Zip64Reader;
import ru.olegcherednik.zip4jvm.model.Zip64;
import ru.olegcherednik.zip4jvm.model.block.Zip64Block;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 20.10.2019
 */
@RequiredArgsConstructor
public final class BlockZip64Reader extends Zip64Reader {

    private final Zip64Block zip64Block;

    @Override
    protected Zip64.EndCentralDirectoryLocator readEndCentralDirectoryLocator(DataInput in) throws IOException {
        return zip64Block.getEndCentralDirectoryLocatorBlock().calc(in, () -> super.readEndCentralDirectoryLocator(in));
    }

    @Override
    protected Zip64.EndCentralDirectory readEndCentralDirectory(DataInput in) throws IOException {
        return zip64Block.getEndCentralDirectoryBlock().calc(in, () -> super.readEndCentralDirectory(in));
    }

}
