package ru.olegcherednik.zip4jvm.view.decompose;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.io.IOUtils;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.model.block.Block;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

/**
 * @author Oleg Cherednik
 * @since 07.12.2019
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
final class Utils {

    public static void print(Path file, Consumer<PrintStream> consumer) throws FileNotFoundException {
        try (PrintStream out = new PrintStream(file.toFile())) {
            consumer.accept(out);
        }
    }

    public static void copyLarge(ZipModel zipModel, Path out, Block block) throws IOException {
        copyLarge(zipModel, out, block.getOffs(), block.getSize());
    }

    public static void copyLarge(ZipModel zipModel, Path out, long offs, long size) throws IOException {
        Path file = zipModel.getSrcFile().getPath();

        try (FileInputStream fis = new FileInputStream(file.toFile()); FileOutputStream fos = new FileOutputStream(out.toFile())) {
            fis.skip(offs);
            IOUtils.copyLarge(fis, fos, 0, size);
        }
    }

    public static Path createSubDir(Path dir, ZipEntry zipEntry, long pos) throws IOException {
        String fileName = zipEntry.getFileName();

        if (zipEntry.isDirectory())
            fileName = fileName.substring(0, fileName.length() - 1);

        fileName = "#" + (pos + 1) + " - " + fileName.replaceAll("[\\/]", "_-_");
        return Files.createDirectories(dir.resolve(fileName));
    }

}
