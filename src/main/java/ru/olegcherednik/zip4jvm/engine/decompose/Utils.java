package ru.olegcherednik.zip4jvm.engine.decompose;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.io.in.SingleZipInputStream;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.model.block.Block;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 07.12.2019
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Utils {

    public static void print(Path file, Consumer<PrintStream> consumer) throws FileNotFoundException {
        try (PrintStream out = new PrintStream(file.toFile())) {
            consumer.accept(out);
        }
    }

    public static void copyLarge(ZipModel zipModel, Path out, Block block) throws IOException {
        Path file = zipModel.getFile();

        try (FileInputStream fis = new FileInputStream(file.toFile()); FileOutputStream fos = new FileOutputStream(out.toFile())) {
            fis.skip(block.getOffs());
            IOUtils.copyLarge(fis, fos, 0, block.getSize());
        }
    }

    public static Function<Block, byte[]> getDataFunc(ZipModel zipModel) {
        return block -> {
            if (block.getSize() > Integer.MAX_VALUE)
                return ArrayUtils.EMPTY_BYTE_ARRAY;

            try (DataInput in = new SingleZipInputStream(zipModel.getFile())) {
                in.skip(block.getOffs());
                return in.readBytes((int)block.getSize());
            } catch(Exception e) {
                e.printStackTrace();
                return ArrayUtils.EMPTY_BYTE_ARRAY;
            }
        };
    }

}