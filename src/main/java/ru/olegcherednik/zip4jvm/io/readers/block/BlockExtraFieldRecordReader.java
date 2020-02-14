package ru.olegcherednik.zip4jvm.io.readers.block;

import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.readers.ExtraFieldRecordReader;
import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.model.block.Block;
import ru.olegcherednik.zip4jvm.model.block.ExtraFieldBlock;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;
import java.util.Map;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 20.10.2019
 */
public class BlockExtraFieldRecordReader extends ExtraFieldRecordReader {

    private final ExtraFieldBlock extraFieldBlock;

    public BlockExtraFieldRecordReader(Map<Integer, Function<Integer, Reader<? extends ExtraField.Record>>> readers,
            ExtraFieldBlock extraFieldBlock) {
        super(readers);
        this.extraFieldBlock = extraFieldBlock;
    }

    @Override
    public ExtraField.Record read(DataInput in) throws IOException {
        Block block = new Block();
        ExtraField.Record record = block.calc(in, () -> super.read(in));
        extraFieldBlock.addRecord(record.getSignature(), block);
        return record;
    }
}
