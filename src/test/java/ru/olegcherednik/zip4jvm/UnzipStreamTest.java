package ru.olegcherednik.zip4jvm;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static ru.olegcherednik.zip4jvm.TestData.dirSrc;
import static ru.olegcherednik.zip4jvm.TestData.fileBentley;
import static ru.olegcherednik.zip4jvm.TestData.fileFerrari;
import static ru.olegcherednik.zip4jvm.TestData.fileNameBentley;
import static ru.olegcherednik.zip4jvm.TestData.fileWiesmann;
import static ru.olegcherednik.zip4jvm.TestData.zipDeflateSolid;
import static ru.olegcherednik.zip4jvm.TestData.zipDeflateSolidPkware;
import static ru.olegcherednik.zip4jvm.TestData.zipDeflateSplit;
import static ru.olegcherednik.zip4jvm.TestDataAssert.copyLarge;
import static ru.olegcherednik.zip4jvm.TestDataAssert.fileBentleyAssert;
import static ru.olegcherednik.zip4jvm.TestDataAssert.fileFerrariAssert;
import static ru.olegcherednik.zip4jvm.TestDataAssert.fileWiesmannAssert;
import static ru.olegcherednik.zip4jvm.Zip4jvmSuite.password;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatFile;

/**
 * @author Oleg Cherednik
 * @since 22.03.2019
 */
@Test
@SuppressWarnings("FieldNamingConvention")
public class UnzipStreamTest {

    private static final Path rootDir = Zip4jvmSuite.generateSubDirNameWithTime(UnzipStreamTest.class);

    @BeforeClass
    public static void createDir() throws IOException {
        Files.createDirectories(rootDir);
    }

    @AfterClass(enabled = Zip4jvmSuite.clear)
    public static void removeDir() throws IOException {
        Zip4jvmSuite.removeDir(rootDir);
    }

    public void shouldUnzipEntryToStreamWhenNoSplit() throws IOException {
        Path actual = rootDir.resolve(fileNameBentley);
        copyLarge(UnzipIt.zip(zipDeflateSolid).stream(dirSrc.relativize(fileBentley).toString()), actual);
        assertThatFile(actual).matches(fileBentleyAssert);
    }

    public void shouldUnzipEntryToStreamWhenSplit() throws IOException {
        Path actual = rootDir.resolve(fileFerrari);
        copyLarge(UnzipIt.zip(zipDeflateSplit).stream(dirSrc.relativize(fileFerrari).toString()), actual);
        assertThatFile(actual).matches(fileFerrariAssert);
    }

    public void shouldUnzipEntryToStreamWhenPkwareNoSplit() throws IOException {
        Path actual = rootDir.resolve(fileWiesmann);
        copyLarge(UnzipIt.zip(zipDeflateSolidPkware).password(password).stream(dirSrc.relativize(fileWiesmann).toString()), actual);
        assertThatFile(actual).matches(fileWiesmannAssert);
    }
}
