package ru.olegcherednik.zip4jvm;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.model.Compression;
import ru.olegcherednik.zip4jvm.model.CompressionLevel;
import ru.olegcherednik.zip4jvm.model.settings.ZipEntrySettings;
import ru.olegcherednik.zip4jvm.model.settings.ZipFileSettings;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static ru.olegcherednik.zip4jvm.TestData.dirBikes;
import static ru.olegcherednik.zip4jvm.TestData.dirCars;
import static ru.olegcherednik.zip4jvm.TestData.fileBentley;
import static ru.olegcherednik.zip4jvm.TestData.fileHonda;
import static ru.olegcherednik.zip4jvm.TestData.fileNameBentley;
import static ru.olegcherednik.zip4jvm.TestData.fileNameHonda;
import static ru.olegcherednik.zip4jvm.TestData.fileNameSaintPetersburg;
import static ru.olegcherednik.zip4jvm.TestData.fileSaintPetersburg;
import static ru.olegcherednik.zip4jvm.TestData.zipDirNameBikes;
import static ru.olegcherednik.zip4jvm.TestData.zipDirNameCars;
import static ru.olegcherednik.zip4jvm.TestDataAssert.zipDirBikesAssert;
import static ru.olegcherednik.zip4jvm.TestDataAssert.zipDirCarsAssert;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatDirectory;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatZipFile;

/**
 * @author Oleg Cherednik
 * @since 26.09.2019
 */
@Test
@SuppressWarnings("FieldNamingConvention")
public class ZipItTest {

    private static final Path rootDir = Zip4jvmSuite.generateSubDirNameWithTime(ZipItTest.class);
    private static final Path defSingleZip = rootDir.resolve("def/single/src.zip");
    private static final Path defMultiZip = rootDir.resolve("def/multi/src.zip");
    private static final Path customSingleZip = rootDir.resolve("custom/single/src.zip");
    private static final Path customMultiZip = rootDir.resolve("custom/multi/src.zip");

    @BeforeClass
    public static void createDir() throws IOException {
        Files.createDirectories(rootDir);
    }

    @AfterClass(enabled = Zip4jvmSuite.clear)
    public static void removeDir() throws IOException {
        Zip4jvmSuite.removeDir(rootDir);
    }

    public void shouldCreateZipWhenAddRegularFileAndDefaultSettings() throws IOException {
        ZipIt.zip(defSingleZip).add(fileBentley);
        assertThatDirectory(defSingleZip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(defSingleZip).root().hasDirectories(0).hasFiles(1);
        assertThatZipFile(defSingleZip).file(fileNameBentley).exists().hasSize(1_395_362);
    }

    public void shouldCreateZipWhenAddDirectoryAndDefaultSettings() throws IOException {
        Path zip = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");

        ZipIt.zip(zip).add(dirCars);
        assertThatDirectory(zip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(zip).root().hasDirectories(1).hasFiles(0);
        assertThatZipFile(zip).directory(zipDirNameCars).matches(zipDirCarsAssert);
    }

    @Test(dependsOnMethods = "shouldCreateZipWhenAddRegularFileAndDefaultSettings")
    public void shouldAddRegularFileWhenZipExistsDefaultSettings() throws IOException {
        ZipIt.zip(defSingleZip).add(fileSaintPetersburg);
        assertThatDirectory(defSingleZip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(defSingleZip).root().hasDirectories(0).hasFiles(2);
        assertThatZipFile(defSingleZip).file(fileNameBentley).exists().hasSize(1_395_362);
        assertThatZipFile(defSingleZip).file(fileNameSaintPetersburg).exists().hasSize(1_074_836);
    }

    @Test(dependsOnMethods = "shouldAddRegularFileWhenZipExistsDefaultSettings")
    public void shouldAddDirectoryWhenZipExistsDefaultSettings() throws IOException {
        ZipIt.zip(defSingleZip).add(dirCars);
        assertThatDirectory(defSingleZip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(defSingleZip).root().hasDirectories(1).hasFiles(2);
        assertThatZipFile(defSingleZip).file(fileNameBentley).exists().hasSize(1_395_362);
        assertThatZipFile(defSingleZip).file(fileNameSaintPetersburg).exists().hasSize(1_074_836);
        assertThatZipFile(defSingleZip).directory(zipDirNameCars).matches(zipDirCarsAssert);
    }

    public void shouldCreateZipWhenAddRegularFilesAndDirectoriesAndDefaultSettings() throws IOException {
        ZipIt.zip(defMultiZip).add(Arrays.asList(fileHonda, dirCars));
        assertThatDirectory(defMultiZip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(defMultiZip).root().hasDirectories(1).hasFiles(1);
        assertThatZipFile(defMultiZip).file(fileNameHonda).exists().hasSize(154_591);
        assertThatZipFile(defMultiZip).directory(zipDirNameCars).matches(zipDirCarsAssert);
    }

    @Test(dependsOnMethods = "shouldCreateZipWhenAddRegularFilesAndDirectoriesAndDefaultSettings")
    public void shouldAddRegularFilesAndDirectoriesWhenZipExistsDefaultSettings() throws IOException {
        ZipIt.zip(defMultiZip).add(Arrays.asList(fileSaintPetersburg, dirBikes));
        assertThatDirectory(defMultiZip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(defMultiZip).root().hasDirectories(2).hasFiles(2);
        assertThatZipFile(defMultiZip).file(fileNameHonda).exists().hasSize(154_591);
        assertThatZipFile(defMultiZip).file(fileNameSaintPetersburg).exists().hasSize(1_074_836);
        assertThatZipFile(defMultiZip).directory(zipDirNameCars).matches(zipDirCarsAssert);
        assertThatZipFile(defMultiZip).directory(zipDirNameBikes).matches(zipDirBikesAssert);
    }

    public void shouldThrowExceptionWhenAddNullPathAndDefaultSettings() {
        assertThatThrownBy(() -> ZipIt.zip(defSingleZip).add((Path)null)).isExactlyInstanceOf(NullPointerException.class);
    }

    public void shouldThrowExceptionWhenAddNullPathAndCustomSettings() {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();
        ZipFileSettings settings = ZipFileSettings.builder().entrySettingsProvider(fileName -> entrySettings).build();
        assertThatThrownBy(() -> ZipIt.zip(customSingleZip).settings(settings).add((Path)null)).isExactlyInstanceOf(NullPointerException.class);
    }

    public void shouldCreateZipWhenAddRegularFileAndCustomSettings() throws IOException {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();
        ZipFileSettings settings = ZipFileSettings.builder().entrySettingsProvider(fileName -> entrySettings).build();

        ZipIt.zip(customSingleZip).settings(settings).add(fileBentley);
        assertThatDirectory(customSingleZip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(customSingleZip).root().hasDirectories(0).hasFiles(1);
        assertThatZipFile(customSingleZip).file(fileNameBentley).exists().hasSize(1_395_362);
    }

    public void shouldCreateZipWhenAddDirectoryAndCustomSettings() throws IOException {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();
        ZipFileSettings settings = ZipFileSettings.builder().entrySettingsProvider(fileName -> entrySettings).build();

        Path zip = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");

        ZipIt.zip(zip).settings(settings).add(dirCars);
        assertThatDirectory(zip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(zip).root().hasDirectories(1).hasFiles(0);
        assertThatZipFile(zip).directory(zipDirNameCars).matches(zipDirCarsAssert);
    }

    @Test(dependsOnMethods = "shouldCreateZipWhenAddRegularFileAndCustomSettings")
    public void shouldAddRegularFileWhenZipExistsCustomSettings() throws IOException {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();
        ZipFileSettings settings = ZipFileSettings.builder().entrySettingsProvider(fileName -> entrySettings).build();

        ZipIt.zip(customSingleZip).settings(settings).add(fileSaintPetersburg);
        assertThatDirectory(customSingleZip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(customSingleZip).root().hasDirectories(0).hasFiles(2);
        assertThatZipFile(customSingleZip).file(fileNameBentley).exists().hasSize(1_395_362);
        assertThatZipFile(customSingleZip).file(fileNameSaintPetersburg).exists().hasSize(1_074_836);
    }

    @Test(dependsOnMethods = "shouldAddRegularFileWhenZipExistsCustomSettings")
    public void shouldAddDirectoryWhenZipExistsCustomSettings() throws IOException {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();
        ZipFileSettings settings = ZipFileSettings.builder().entrySettingsProvider(fileName -> entrySettings).build();

        ZipIt.zip(customSingleZip).settings(settings).add(dirCars);
        assertThatDirectory(customSingleZip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(customSingleZip).root().hasDirectories(1).hasFiles(2);
        assertThatZipFile(customSingleZip).file(fileNameBentley).exists().hasSize(1_395_362);
        assertThatZipFile(customSingleZip).file(fileNameSaintPetersburg).exists().hasSize(1_074_836);
        assertThatZipFile(customSingleZip).directory(zipDirNameCars).matches(zipDirCarsAssert);
    }

    public void shouldCreateZipWhenAddRegularFilesAndDirectoriesAndCustomSettings() throws IOException {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();
        ZipFileSettings settings = ZipFileSettings.builder().entrySettingsProvider(fileName -> entrySettings).build();

        ZipIt.zip(customMultiZip).settings(settings).add(Arrays.asList(fileHonda, dirCars));
        assertThatDirectory(customMultiZip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(customMultiZip).root().hasDirectories(1).hasFiles(1);
        assertThatZipFile(customMultiZip).file(fileNameHonda).exists().hasSize(154_591);
        assertThatZipFile(customMultiZip).directory(zipDirNameCars).matches(zipDirCarsAssert);
    }

    @Test(dependsOnMethods = "shouldCreateZipWhenAddRegularFilesAndDirectoriesAndCustomSettings")
    public void shouldAddRegularFilesAndDirectoriesWhenZipExistsCustomSettings() throws IOException {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();
        ZipFileSettings settings = ZipFileSettings.builder().entrySettingsProvider(fileName -> entrySettings).build();

        ZipIt.zip(customMultiZip).settings(settings).add(Arrays.asList(fileSaintPetersburg, dirBikes));
        assertThatDirectory(customMultiZip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(customMultiZip).root().hasDirectories(2).hasFiles(2);
        assertThatZipFile(customMultiZip).file(fileNameHonda).exists().hasSize(154_591);
        assertThatZipFile(customMultiZip).file(fileNameSaintPetersburg).exists().hasSize(1_074_836);
        assertThatZipFile(customMultiZip).directory(zipDirNameCars).matches(zipDirCarsAssert);
        assertThatZipFile(customMultiZip).directory(zipDirNameBikes).matches(zipDirBikesAssert);
    }

}
