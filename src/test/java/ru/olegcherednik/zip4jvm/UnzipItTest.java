package ru.olegcherednik.zip4jvm;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Ignore;
import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.model.settings.UnzipSettings;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static ru.olegcherednik.zip4jvm.TestData.dirNameBikes;
import static ru.olegcherednik.zip4jvm.TestData.dirNameCars;
import static ru.olegcherednik.zip4jvm.TestData.fileNameBentley;
import static ru.olegcherednik.zip4jvm.TestData.fileNameFerrari;
import static ru.olegcherednik.zip4jvm.TestData.fileNameSaintPetersburg;
import static ru.olegcherednik.zip4jvm.TestData.zipDeflateSolid;
import static ru.olegcherednik.zip4jvm.TestData.zipDeflateSplit;
import static ru.olegcherednik.zip4jvm.TestDataAssert.dirBikesAssert;
import static ru.olegcherednik.zip4jvm.TestDataAssert.fileBentleyAssert;
import static ru.olegcherednik.zip4jvm.TestDataAssert.fileFerrariAssert;
import static ru.olegcherednik.zip4jvm.TestDataAssert.fileSaintPetersburgAssert;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatDirectory;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatFile;

/**
 * @author Oleg Cherednik
 * @since 14.03.2019
 */
@Test
@SuppressWarnings("FieldNamingConvention")
public class UnzipItTest {

    private static final Path rootDir = Zip4jvmSuite.generateSubDirName(UnzipItTest.class);

    @BeforeClass
    public static void createDir() throws IOException {
        Files.createDirectories(rootDir);
    }

    @AfterClass(enabled = Zip4jvmSuite.clear)
    public static void removeDir() throws IOException {
        Zip4jvmSuite.removeDir(rootDir);
    }

    public void shouldUnzipRequiredFiles() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodNameWithTme(rootDir);
        List<String> fileNames = Arrays.asList(fileNameSaintPetersburg, dirNameCars + '/' + fileNameBentley);
        UnzipIt.zip(zipDeflateSolid).destDir(destDir).extract(fileNames);

        assertThatDirectory(destDir).exists().hasDirectories(0).hasFiles(2);
        assertThatFile(destDir.resolve(fileNameSaintPetersburg)).matches(fileSaintPetersburgAssert);
        assertThatFile(destDir.resolve(fileNameBentley)).matches(fileBentleyAssert);
    }

    @Test
    @Ignore
    public void shouldUnzipRequiredFilesWhenSplit() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodNameWithTme(rootDir);
        List<String> fileNames = Arrays.asList("saint-fileNameSaintPetersburg.jpg", dirNameCars + '/' + fileNameBentley);
        UnzipIt.zip(zipDeflateSplit).destDir(destDir).extract(fileNames);

        assertThatDirectory(destDir).exists().hasDirectories(0).hasFiles(2);
        assertThatFile(destDir.resolve(fileNameSaintPetersburg)).matches(fileSaintPetersburgAssert);
        assertThatFile(destDir.resolve(fileNameBentley)).matches(fileBentleyAssert);
    }

    public void shouldUnzipOneFile() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodNameWithTme(rootDir);
        UnzipIt.zip(zipDeflateSolid).destDir(destDir).extract(dirNameCars + '/' + fileNameFerrari);

        assertThatDirectory(destDir).exists().hasDirectories(0).hasFiles(1);
        assertThatFile(destDir.resolve(fileNameFerrari)).matches(fileFerrariAssert);
    }

    public void shouldUnzipFolder() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodNameWithTme(rootDir);
        UnzipIt.zip(zipDeflateSolid).destDir(destDir).extract(dirNameBikes);

        assertThatDirectory(destDir).exists().hasDirectories(1).hasFiles(0);
        assertThatDirectory(destDir.resolve(dirNameBikes)).matches(dirBikesAssert);
    }

    public void shouldExtractZipArchiveWhenEntryNameWithCustomCharset() throws IOException, URISyntaxException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodNameWithTme(rootDir);
        Path zip = Paths.get(UnzipItTest.class.getResource("/zip/cjk_filename.zip").toURI()).toAbsolutePath();

        UnzipSettings settings = UnzipSettings.builder().charset(Charset.forName("GBK")).build();

        UnzipIt.zip(zip).destDir(destDir).settings(settings).extract();

        assertThatDirectory(destDir).hasDirectories(0).hasFiles(2);
        assertThatDirectory(destDir).file("fff - 副本.txt").exists();
    }

    public void shouldExtractZipArchiveWhenZipWasCreatedUnderMac() throws IOException, URISyntaxException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodNameWithTme(rootDir);
        Path zip = Paths.get(UnzipItTest.class.getResource("/zip/macos_10.zip").toURI()).toAbsolutePath();

        UnzipIt.zip(zip).destDir(destDir).extract();

        int a = 0;
        a++;
//    TODO commented tests
//        assertThatDirectory(destDir).hasDirectories(0).hasFiles(2);
//        assertThatDirectory(destDir).file("fff - 副本.txt").exists();
    }

}
