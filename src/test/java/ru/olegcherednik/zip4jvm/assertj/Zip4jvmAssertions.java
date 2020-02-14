package ru.olegcherednik.zip4jvm.assertj;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.assertj.core.api.Assertions;
import ru.olegcherednik.zip4jvm.model.ZipModel;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 24.03.2019
 */
@SuppressWarnings({ "ExtendsUtilityClass", "MethodCanBeVariableArityMethod" })
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Zip4jvmAssertions extends Assertions {

    public static ZipFileAssert assertThatZipFile(Path zip) throws IOException {
        return new ZipFileAssert(isSplit(zip) ? new ZipFileSplitDecorator(zip) : new ZipFileSolidNoEncryptedDecorator(zip));
    }

    public static ZipFileAssert assertThatZipFile(Path zip, char[] password) throws IOException {
        return new ZipFileAssert(isSplit(zip) ? new ZipFileSplitDecorator(zip, password) : new ZipFileEncryptedDecoder(zip, password));
    }

    public static DirectoryAssert assertThatDirectory(Path path) {
        return new DirectoryAssert(path);
    }

    public static FileAssert assertThatFile(Path path) {
        return new FileAssert(path);
    }

    public static StringLineAssert assertThatStringLine(int pos, String str) {
        return new StringLineAssert(pos, str);
    }

    private static boolean isSplit(Path zip) {
        return Files.exists(ZipModel.getDiskFile(zip, 1));
    }

}
