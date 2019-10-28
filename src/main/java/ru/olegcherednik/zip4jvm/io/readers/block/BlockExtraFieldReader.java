package ru.olegcherednik.zip4jvm.io.readers.block;

import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.io.readers.ExtraFieldReader;
import ru.olegcherednik.zip4jvm.io.readers.ExtraFieldRecordReader;
import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.model.block.Diagnostic;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;
import java.util.Map;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 20.10.2019
 */
public class BlockExtraFieldReader extends ExtraFieldReader {

    private final Diagnostic.ExtraField extraFieldBlock;

    public BlockExtraFieldReader(int size, Map<Integer, Function<Integer, Reader<? extends ExtraField.Record>>> readers,
            Diagnostic.ExtraField extraFieldBlock) {
        super(size, readers);
        this.extraFieldBlock = extraFieldBlock;
    }

    @Override
    protected ExtraField readExtraField(DataInput in) throws IOException {
        extraFieldBlock.addRecord();
        return extraFieldBlock.getRecord().calc(in, () -> super.readExtraField(in));
    }

    @Override
    protected ExtraFieldRecordReader getExtraFieldRecordReader() {
        return new BlockExtraFieldRecordReader(readers, extraFieldBlock);
    }

}
