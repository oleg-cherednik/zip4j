package ru.olegcherednik.zip4jvm.io.in.file;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.in.data.SingleZipInputStream;
import ru.olegcherednik.zip4jvm.io.out.data.SplitZipOutputStream;
import ru.olegcherednik.zip4jvm.model.ZipModel;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 20.01.2020
 */
@Getter
@RequiredArgsConstructor
final class StandardSrcFile extends SrcFile {

    private final Path path;

    @Override
    public DataInputFile dataInputFile() throws IOException {
        return new LittleEndianReadFile(path);
    }

    @Override
    public boolean isSplit() throws IOException {
        Path file = ZipModel.getDiskFile(path, 1);

        if (!Files.exists(file))
            return false;

        try (DataInput in = new SingleZipInputStream(SrcFile.of(file))) {
            return in.readDwordSignature() == SplitZipOutputStream.SPLIT_SIGNATURE;
        }
    }

    @Override
    public String toString() {
        return path.toString();
    }

}
