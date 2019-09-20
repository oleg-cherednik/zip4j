package ru.olegcherednik.zip4jvm;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.model.Compression;
import ru.olegcherednik.zip4jvm.model.CompressionLevel;
import ru.olegcherednik.zip4jvm.model.Encryption;
import ru.olegcherednik.zip4jvm.model.settings.ZipEntrySettings;
import ru.olegcherednik.zip4jvm.model.settings.ZipFileSettings;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Function;

import static ru.olegcherednik.zip4jvm.TestData.fileDucati;
import static ru.olegcherednik.zip4jvm.TestData.fileHonda;
import static ru.olegcherednik.zip4jvm.TestData.fileKawasaki;
import static ru.olegcherednik.zip4jvm.TestData.fileNameBentley;
import static ru.olegcherednik.zip4jvm.TestData.fileNameDucati;
import static ru.olegcherednik.zip4jvm.TestData.fileNameFerrari;
import static ru.olegcherednik.zip4jvm.TestData.fileNameHonda;
import static ru.olegcherednik.zip4jvm.TestData.fileNameKawasaki;
import static ru.olegcherednik.zip4jvm.TestData.fileNameSuzuki;
import static ru.olegcherednik.zip4jvm.TestData.fileNameWiesmann;
import static ru.olegcherednik.zip4jvm.TestData.fileSuzuki;
import static ru.olegcherednik.zip4jvm.TestData.filesDirBikes;
import static ru.olegcherednik.zip4jvm.TestData.filesDirCars;
import static ru.olegcherednik.zip4jvm.TestData.filesDirSrc;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatDirectory;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatZipFile;

/**
 * @author Oleg Cherednik
 * @since 01.09.2019
 */
@Test
@SuppressWarnings("FieldNamingConvention")
public class ZipFileTest {

    private static final Path rootDir = Zip4jvmSuite.generateSubDirNameWithTime(ZipFileTest.class);
    private static final Path file = rootDir.resolve("createZipArchiveAndAddFiles/src.zip");

    @BeforeClass
    public static void createDir() throws IOException {
        Files.createDirectories(rootDir);
    }

    @AfterClass(enabled = Zip4jvmSuite.clear)
    public static void removeDir() throws IOException {
        Zip4jvmSuite.removeDir(rootDir);
    }

    public void shouldCreateZipFileWhenUseZipFileAndAddFiles() throws IOException {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();

        try (ZipFile.Writer zipFile = ZipFile.write(file, fileName -> entrySettings)) {
            zipFile.add(Zip4jvmSuite.dirCars.resolve("bentley-continental.jpg"));
            zipFile.add(Zip4jvmSuite.dirCars.resolve("ferrari-458-italia.jpg"));
            zipFile.add(Zip4jvmSuite.dirCars.resolve("wiesmann-gt-mf5.jpg"));
        }

        assertThatDirectory(file.getParent()).exists().hasSubDirectories(0).hasFiles(1);
        assertThatZipFile(file).exists().rootEntry().hasSubDirectories(0).hasFiles(3);
        assertThatZipFile(file).file("bentley-continental.jpg").exists().isImage().hasSize(1_395_362);
        assertThatZipFile(file).file("ferrari-458-italia.jpg").exists().isImage().hasSize(320_894);
        assertThatZipFile(file).file("wiesmann-gt-mf5.jpg").exists().isImage().hasSize(729_633);
    }

    @Test(dependsOnMethods = "shouldCreateZipFileWhenUseZipFileAndAddFiles")
    public void shouldAddFilesToExistedZipWhenUseZipFile() throws IOException {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();

        try (ZipFile.Writer zipFile = ZipFile.write(file, fileName -> entrySettings)) {
            zipFile.add(fileDucati);
            zipFile.add(fileHonda);
            zipFile.add(fileKawasaki);
            zipFile.add(fileSuzuki);
        }

        assertThatDirectory(file.getParent()).exists().hasSubDirectories(0).hasFiles(1);
        assertThatZipFile(file).exists().rootEntry().hasSubDirectories(0).hasFiles(7);
        assertThatZipFile(file).file(fileNameBentley).exists().isImage().hasSize(1_395_362);
        assertThatZipFile(file).file(fileNameFerrari).exists().isImage().hasSize(320_894);
        assertThatZipFile(file).file(fileNameWiesmann).exists().isImage().hasSize(729_633);
        assertThatZipFile(file).file(fileNameDucati).exists().isImage().hasSize(293_823);
        assertThatZipFile(file).file(fileNameHonda).exists().isImage().hasSize(154_591);
        assertThatZipFile(file).file(fileNameKawasaki).exists().isImage().hasSize(167_026);
        assertThatZipFile(file).file(fileNameSuzuki).exists().isImage().hasSize(287_349);
    }

    public void shouldCreateZipFileWithEntryCommentWhenUseZipFile() throws IOException {
        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");

        Function<String, ZipEntrySettings> entrySettingsProvider = fileName -> {
            if ("bentley-continental.jpg".equals(fileName))
                return ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).comment("bentley-continental").build();
            if ("ferrari-458-italia.jpg".equals(fileName))
                return ZipEntrySettings.builder().compression(Compression.DEFLATE, CompressionLevel.NORMAL).comment("ferrari-458-italia").build();
            if ("wiesmann-gt-mf5.jpg".equals(fileName))
                return ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).comment("wiesmann-gt-mf5").build();
            return ZipEntrySettings.DEFAULT;
        };

        try (ZipFile.Writer zipFile = ZipFile.write(file, entrySettingsProvider)) {
            zipFile.add(Zip4jvmSuite.dirCars.resolve("bentley-continental.jpg"));
            zipFile.add(Zip4jvmSuite.dirCars.resolve("ferrari-458-italia.jpg"));
            zipFile.add(Zip4jvmSuite.dirCars.resolve("wiesmann-gt-mf5.jpg"));
        }

        assertThatDirectory(file.getParent()).exists().hasSubDirectories(0).hasFiles(1);
        assertThatZipFile(file).exists().rootEntry().hasSubDirectories(0).hasFiles(3);
        assertThatZipFile(file).file("bentley-continental.jpg").exists().isImage().hasSize(1_395_362).hasComment("bentley-continental");
        assertThatZipFile(file).file("ferrari-458-italia.jpg").exists().isImage().hasSize(320_894).hasComment("ferrari-458-italia");
        assertThatZipFile(file).file("wiesmann-gt-mf5.jpg").exists().isImage().hasSize(729_633).hasComment("wiesmann-gt-mf5");
    }

    // TODO add unzip tests for such ZipFile

    public void shouldCreateZipFileWithEntryDifferentEncryptionAndPasswordWhenUseZipFile() throws IOException {
        Function<String, ZipEntrySettings> entrySettingsProvider = fileName -> {
            if ("bentley-continental.jpg".equals(fileName))
                return ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();
            if ("ferrari-458-italia.jpg".equals(fileName))
                return ZipEntrySettings.builder()
                                       .compression(Compression.STORE, CompressionLevel.NORMAL)
                                       .encryption(Encryption.PKWARE, "1".toCharArray()).build();
            if ("wiesmann-gt-mf5.jpg".equals(fileName))
                return ZipEntrySettings.builder()
                                       .compression(Compression.STORE, CompressionLevel.NORMAL)
                                       .encryption(Encryption.AES_256, "2".toCharArray()).build();
            return ZipEntrySettings.DEFAULT.toBuilder().password(Zip4jvmSuite.password).build();
        };

        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");

        try (ZipFile.Writer zipFile = ZipFile.write(file, entrySettingsProvider)) {
            zipFile.add(Zip4jvmSuite.dirCars.resolve("bentley-continental.jpg"));
            zipFile.add(Zip4jvmSuite.dirCars.resolve("ferrari-458-italia.jpg"));
            zipFile.add(Zip4jvmSuite.dirCars.resolve("wiesmann-gt-mf5.jpg"));
        }

        assertThatDirectory(file.getParent()).exists().hasSubDirectories(0).hasFiles(1);
//        assertThatZipFile(file).exists().rootEntry().hasSubDirectories(0).hasFiles(3);
//        assertThatZipFile(file).file("bentley-continental.jpg").exists().isImage().hasSize(1_395_362).hasComment("bentley-continental");
//        assertThatZipFile(file).file("ferrari-458-italia.jpg").exists().isImage().hasSize(320_894).hasComment("ferrari-458-italia");
//        assertThatZipFile(file).file("wiesmann-gt-mf5.jpg").exists().isImage().hasSize(729_633).hasComment("wiesmann-gt-mf5");
    }

    public void shouldCreateZipFileWithContentWhenUseZipFile() throws IOException {
        Function<String, ZipEntrySettings> entrySettingsProvider = fileName -> {
            if (fileName.startsWith("Star Wars/"))
                return ZipEntrySettings.builder().compression(Compression.DEFLATE, CompressionLevel.NORMAL).build();
            if (!fileName.contains("/"))
                return ZipEntrySettings.builder()
                                       .compression(Compression.DEFLATE, CompressionLevel.MAXIMUM)
                                       .encryption(Encryption.PKWARE, Zip4jvmSuite.password).build();
            return ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();
        };

        ZipFileSettings zipFileSettings = ZipFileSettings.builder()
                                                         .comment("Global Comment")
                                                         .entrySettingsProvider(entrySettingsProvider).build();

        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");

        try (ZipFile.Writer zipFile = ZipFile.write(file, zipFileSettings)) {
            zipFile.add(filesDirBikes);
            zipFile.add(filesDirCars);
            zipFile.add(filesDirSrc);
        }

//        assertThatDirectory(file.getParent()).exists().hasSubDirectories(0).hasFiles(1);
//        assertThatZipFile(file).exists().rootEntry().hasSubDirectories(0).hasFiles(3);
//        assertThatZipFile(file).file("bentley-continental.jpg").exists().isImage().hasSize(1_395_362);
//        assertThatZipFile(file).file("ferrari-458-italia.jpg").exists().isImage().hasSize(320_894);
//        assertThatZipFile(file).file("wiesmann-gt-mf5.jpg").exists().isImage().hasSize(729_633);
    }

    public void shouldCreateZipFileWithEmptyDirectoryWhenAddEmptyDirectory() throws IOException {
        ZipFileSettings zipFileSettings = ZipFileSettings.builder()
                                                         .entrySettingsProvider(fileName -> ZipEntrySettings.builder().build())
                                                         .build();

        Path zip = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");

        try (ZipFile.Writer zipFile = ZipFile.write(zip, zipFileSettings)) {
            zipFile.add(Zip4jvmSuite.emptyDir);
        }

        assertThatDirectory(zip.getParent()).exists().hasSubDirectories(0).hasFiles(1);
        assertThatZipFile(zip).exists().rootEntry().hasSubDirectories(1).hasFiles(0);
//        assertThatZipFile(file).file("bentley-continental.jpg").exists().isImage().hasSize(1_395_362);
//        assertThatZipFile(file).file("ferrari-458-italia.jpg").exists().isImage().hasSize(320_894);
//        assertThatZipFile(file).file("wiesmann-gt-mf5.jpg").exists().isImage().hasSize(729_633);
    }
}
