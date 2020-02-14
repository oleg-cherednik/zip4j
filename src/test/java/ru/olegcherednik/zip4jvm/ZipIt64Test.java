package ru.olegcherednik.zip4jvm;

import org.apache.commons.io.IOUtils;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.io.in.file.SrcFile;
import ru.olegcherednik.zip4jvm.model.Charsets;
import ru.olegcherednik.zip4jvm.model.Compression;
import ru.olegcherednik.zip4jvm.model.CompressionLevel;
import ru.olegcherednik.zip4jvm.model.Encryption;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.model.builders.ZipModelBuilder;
import ru.olegcherednik.zip4jvm.model.settings.ZipEntrySettings;
import ru.olegcherednik.zip4jvm.model.settings.ZipSettings;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static ru.olegcherednik.zip4jvm.TestData.contentDirSrc;
import static ru.olegcherednik.zip4jvm.TestData.fileBentley;
import static ru.olegcherednik.zip4jvm.TestData.fileNameBentley;
import static ru.olegcherednik.zip4jvm.TestDataAssert.rootAssert;
import static ru.olegcherednik.zip4jvm.Zip4jvmSuite.SIZE_1MB;
import static ru.olegcherednik.zip4jvm.Zip4jvmSuite.password;
import static ru.olegcherednik.zip4jvm.Zip4jvmSuite.passwordStr;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatDirectory;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatZipFile;

/**
 * @author Oleg Cherednik
 * @since 06.04.2019
 */
@Test
@SuppressWarnings({ "FieldNamingConvention", "NewClassNamingConvention" })
public class ZipIt64Test {

    private static final Path rootDir = Zip4jvmSuite.generateSubDirNameWithTime(ZipIt64Test.class);

    private Path zipSimple;
    private Path zipAes;
    private Path zipSplit;
    private Path zipManyEntries;
    private Path zipHugeEntry;

    @BeforeClass
    public static void createDir() throws IOException {
        Files.createDirectories(rootDir);
    }

    @AfterClass(enabled = Zip4jvmSuite.clear)
    public static void removeDir() throws IOException {
        Zip4jvmSuite.removeDir(rootDir);
    }

    public void shouldZipWhenZip64() throws IOException {
        ZipSettings settings = ZipSettings.builder().zip64(true).build();

        zipSimple = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");
        ZipIt.zip(zipSimple).settings(settings).add(contentDirSrc);

        assertThatDirectory(zipSimple.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(zipSimple).root().matches(rootAssert);
    }

    @Test(dependsOnMethods = "shouldZipWhenZip64")
    public void shouldUnzipWhenZip64() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        UnzipIt.zip(zipSimple).destDir(destDir).extract();
        assertThatDirectory(destDir).matches(rootAssert);
    }

    public void shouldZipWhenZip64AndAesEncryption() throws IOException {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder().encryption(Encryption.AES_256, password).build();
        ZipSettings settings = ZipSettings.builder()
                                          .entrySettingsProvider(fileName -> entrySettings)
                                          .comment("password: " + passwordStr)
                                          .zip64(true).build();

        zipAes = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");
        ZipIt.zip(zipAes).settings(settings).add(contentDirSrc);

        assertThatDirectory(zipAes.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(zipAes, password).root().matches(rootAssert);
    }

    @Test(dependsOnMethods = "shouldZipWhenZip64AndAesEncryption")
    public void shouldUnzipWhenZip64AndAesEncryption() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        UnzipIt.zip(zipAes).destDir(destDir).password(password).extract();
        assertThatDirectory(destDir).matches(rootAssert);
    }

    public void shouldZipWhenZip64AndSplit() throws IOException {
        ZipSettings settings = ZipSettings.builder().splitSize(SIZE_1MB).zip64(true).build();

        zipSplit = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");
        ZipIt.zip(zipSplit).settings(settings).add(contentDirSrc);

        // TODO it seems it could be checked with commons-compress
//        assertThatDirectory(zipFile.getParent()).exists().hasSubDirectories(0).hasFiles(1);
//        assertThatZipFile(zipFile).directory("/").matches(TestUtils.zipRootDirAssert);
    }

    @Test(dependsOnMethods = "shouldZipWhenZip64AndSplit")
    public void shouldUnzipWhenZip64AndSplit() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        UnzipIt.zip(zipSplit).destDir(destDir).extract();
        assertThatDirectory(destDir).matches(rootAssert);
    }

    public void shouldUseZip64WhenTotalEntriesOverFFFF() throws IOException {
        zipManyEntries = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");

        try (ZipFile.Writer zipFile = ZipIt.zip(zipManyEntries).open()) {
            IntStream.rangeClosed(1, ZipModel.MAX_TOTAL_ENTRIES + 1)
                     .mapToObj(i -> "file_" + i + ".txt")
                     .map(fileName -> ZipFile.Entry.builder()
                                                   .inputStreamSupplier(() -> IOUtils.toInputStream(fileName, Charsets.UTF_8))
                                                   .fileName(fileName).build())
                     .forEach(zipFile::add);
        }

        ZipModel zipModel = ZipModelBuilder.read(SrcFile.of(zipManyEntries));

        assertThatDirectory(zipManyEntries.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThat(zipModel.getEntryNames()).hasSize(ZipModel.MAX_TOTAL_ENTRIES + 1);
        assertThat(zipModel.isZip64()).isTrue();
    }

//    // TODO it works but it's too slow
//    @Test(dependsOnMethods = "shouldUseZip64WhenTotalEntriesOverFFFF")
//    public void shouldUnzipZip64WhenTotalEntriesOverFFFF() throws IOException {
//        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
//        UnzipIt.extract(zipManyEntries, destDir);
//        assertThatDirectory(destDir).hasDirectories(0).hasFiles(ZipModel.MAX_TOTAL_ENTRIES + 1);
//    }

    public void shouldUseZip64WhenEntrySizeOverFFFFFFFF() throws IOException {
        Path dir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        Files.createDirectories(dir);

        Path file = dir.resolve("file.txt");

        try (RandomAccessFile f = new RandomAccessFile(file.toFile(), "rw")) {
            f.setLength(ZipModel.MAX_ENTRY_SIZE + 1);
        }

        zipHugeEntry = dir.resolve("src.zip");
        ZipEntrySettings entrySettings = ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();
        ZipSettings settings = ZipSettings.builder().entrySettingsProvider(fileNam -> entrySettings).build();
        ZipIt.zip(zipHugeEntry).settings(settings).add(Arrays.asList(file, fileBentley));

        ZipModel zipModel = ZipModelBuilder.read(SrcFile.of(zipHugeEntry));
        assertThat(zipModel.getZipEntryByFileName("file.txt").getUncompressedSize()).isEqualTo(ZipModel.MAX_ENTRY_SIZE + 1);
        assertThat(zipModel.getZipEntryByFileName(fileNameBentley).getUncompressedSize()).isEqualTo(1_395_362);

        // TODO asserts in zip should be using
    }

}
