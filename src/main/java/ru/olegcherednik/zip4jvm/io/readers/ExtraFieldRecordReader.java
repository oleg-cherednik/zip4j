package ru.olegcherednik.zip4jvm.io.readers;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang.ArrayUtils;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;
import java.util.Map;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 20.10.2019
 */
@RequiredArgsConstructor
public class ExtraFieldRecordReader implements Reader<ExtraField.Record> {

    private final Map<Integer, Function<Integer, Reader<? extends ExtraField.Record>>> readers;

    @Override
    public ExtraField.Record read(DataInput in) throws IOException {
        int signature = in.readWordSignature();
        int size = in.readWord();

        if (readers.containsKey(signature))
            return readers.get(signature).apply(size).read(in);

        byte[] data = in.readBytes(size);
        return ExtraField.Record.Unknown.builder()
                                        .signature(signature)
                                        .data(data == null ? ArrayUtils.EMPTY_BYTE_ARRAY : data).build();
    }
}
