package ru.olegcherednik.zip4jvm.utils.function;

import ru.olegcherednik.zip4jvm.io.in.data.DataInput;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 07.09.2019
 */
@FunctionalInterface
public interface Reader<T> {

    T read(DataInput in) throws IOException;

}
