package ru.olegcherednik.zip4jvm.compatibility;

import de.idyl.winzipaes.AesZipFileEncrypter;
import de.idyl.winzipaes.impl.AESEncrypterJCA;
import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.TestUtils;
import ru.olegcherednik.zip4jvm.Zip4jSuite;
import ru.olegcherednik.zip4jvm.ZipFile;
import ru.olegcherednik.zip4jvm.model.settings.ZipFileReaderSettings;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static ru.olegcherednik.zip4jvm.assertj.Zip4jAssertions.assertThatDirectory;

/**
 * @author Oleg Cherednik
 * @since 15.08.2019
 */
@Test
@SuppressWarnings({ "NewClassNamingConvention", "FieldNamingConvention" })
public class WinZipAesToZip4jCompatibilityTest {

    private static final Path rootDir = Zip4jSuite.generateSubDirNameWithTime(WinZipAesToZip4jCompatibilityTest.class);

    public void winZipAesShouldBeReadableForZip4j() throws IOException {
        Path zip = zipItWithWinZipAes(Zip4jSuite.subDirNameAsMethodName(rootDir));
        Path dir = unzipItWithZip4j(zip);
        assertThatDirectory(dir).matches(TestUtils.dirAssert);
    }

    private static Path zipItWithWinZipAes(Path dir) throws IOException {
        String password = new String(Zip4jSuite.password);
        Path zip = dir.resolve("src.zip");
        Files.createDirectories(zip.getParent());

        AesZipFileEncrypter encrypter = new AesZipFileEncrypter(zip.toFile(), new AESEncrypterJCA());
        encrypter.setComment("password: " + password);

        for (Path file : getDirectoryEntries(Zip4jSuite.srcDir)) {
            if (Files.isDirectory(file))
                continue;
            if ("Oleg Cherednik.txt".equals(file.getFileName().toString()))
                continue;

            String pathForEntry = Zip4jSuite.srcDir.relativize(file).toString();
            encrypter.add(file.toFile(), pathForEntry, password);
        }

        encrypter.close();

        return zip;
    }

    @SuppressWarnings("NewMethodNamingConvention")
    private static Path unzipItWithZip4j(Path zip) throws IOException {
        Path destDir = zip.getParent().resolve("unzip");
        ZipFile.Reader zipFile = ZipFile.read(zip, ZipFileReaderSettings.builder().password(fileName -> Zip4jSuite.password).build());
        zipFile.extract(destDir);

        // WinZipAes does not support empty folders in zip
        Files.createDirectories(destDir.resolve("empty_dir"));
        // WinZipAes uses 'iso-8859-1' for file names
        Files.copy(Zip4jSuite.srcDir.resolve("Oleg Cherednik.txt"), destDir.resolve("Oleg Cherednik.txt"));
        return destDir;
    }

    private static List<Path> getDirectoryEntries(Path dir) {
        try {
            return Files.walk(dir)
                        .filter(path -> Files.isRegularFile(path) || Files.isDirectory(path))
                        .collect(Collectors.toList());
        } catch(IOException e) {
            return Collections.emptyList();
        }
    }

}
