package ru.olegcherednik.zip4jvm.io.writers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.utils.function.Writer;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 14.04.2019
 */
@RequiredArgsConstructor
final class ExtraFieldWriter implements Writer {

    private static final String MARK = ExtraFieldWriter.class.getSimpleName();

    private final ExtraField extraField;

    @Override
    public void write(DataOutput out) throws IOException {
        out.mark(MARK);

        for (ExtraField.Record record : extraField.getRecords())
            record.write(out);

        if (extraField.getSize() != out.getWrittenBytesAmount(MARK))
            throw new Zip4jvmException("Illegal number of written bytes");
    }

}
