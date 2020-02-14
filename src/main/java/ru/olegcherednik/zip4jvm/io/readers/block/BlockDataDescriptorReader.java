package ru.olegcherednik.zip4jvm.io.readers.block;

import lombok.Getter;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.readers.DataDescriptorReader;
import ru.olegcherednik.zip4jvm.model.DataDescriptor;
import ru.olegcherednik.zip4jvm.model.block.Block;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 26.10.2019
 */
public class BlockDataDescriptorReader implements Reader<DataDescriptor> {

    private final DataDescriptorReader reader;
    @Getter
    private final Block block = new Block();

    public BlockDataDescriptorReader(boolean zip64) {
        reader = DataDescriptorReader.get(zip64);
    }

    @Override
    public DataDescriptor read(DataInput in) throws IOException {
        return block.calc(in, () -> reader.read(in));
    }

}
