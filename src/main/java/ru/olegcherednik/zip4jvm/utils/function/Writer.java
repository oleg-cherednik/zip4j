package ru.olegcherednik.zip4jvm.utils.function;

import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 15.09.2019
 */
@FunctionalInterface
public interface Writer {

    void write(DataOutput out) throws IOException;

}
