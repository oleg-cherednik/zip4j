package ru.olegcherednik.zip4jvm.encryption;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.ArrayUtils;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.UnzipIt;
import ru.olegcherednik.zip4jvm.Zip4jvmSuite;
import ru.olegcherednik.zip4jvm.ZipIt;
import ru.olegcherednik.zip4jvm.exception.EmptyPasswordException;
import ru.olegcherednik.zip4jvm.exception.IncorrectPasswordException;
import ru.olegcherednik.zip4jvm.model.Compression;
import ru.olegcherednik.zip4jvm.model.CompressionLevel;
import ru.olegcherednik.zip4jvm.model.Encryption;
import ru.olegcherednik.zip4jvm.model.settings.UnzipSettings;
import ru.olegcherednik.zip4jvm.model.settings.ZipEntrySettings;
import ru.olegcherednik.zip4jvm.model.settings.ZipSettings;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static ru.olegcherednik.zip4jvm.TestData.contentDirSrc;
import static ru.olegcherednik.zip4jvm.TestData.filesDirBikes;
import static ru.olegcherednik.zip4jvm.TestData.filesDirCars;
import static ru.olegcherednik.zip4jvm.TestData.zipStoreSolidPkware;
import static ru.olegcherednik.zip4jvm.TestData.zipStoreSplitPkware;
import static ru.olegcherednik.zip4jvm.TestDataAssert.dirBikesAssert;
import static ru.olegcherednik.zip4jvm.TestDataAssert.dirCarsAssert;
import static ru.olegcherednik.zip4jvm.TestDataAssert.rootAssert;
import static ru.olegcherednik.zip4jvm.Zip4jvmSuite.password;
import static ru.olegcherednik.zip4jvm.Zip4jvmSuite.passwordStr;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatDirectory;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatZipFile;

/**
 * @author Oleg Cherednik
 * @since 28.07.2019
 */
@Slf4j
@Test
@SuppressWarnings("FieldNamingConvention")
public class EncryptionPkwareTest {

    private static final Path rootDir = Zip4jvmSuite.generateSubDirNameWithTime(EncryptionPkwareTest.class);

    @BeforeClass
    public static void createDir() throws IOException {
        Files.createDirectories(rootDir);
    }

    @AfterClass(enabled = Zip4jvmSuite.clear)
    public static void removeDir() throws IOException {
        Zip4jvmSuite.removeDir(rootDir);
    }

    public void shouldCreateNewZipWithFolderAndPkwareEncryption() throws IOException {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder()
                                                         .compression(Compression.DEFLATE, CompressionLevel.NORMAL)
                                                         .encryption(Encryption.PKWARE, password).build();
        ZipSettings settings = ZipSettings.builder()
                                          .entrySettingsProvider(fileName -> entrySettings)
                                          .comment("password: " + passwordStr).build();

        Path zip = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");

        ZipIt.zip(zip).settings(settings).add(contentDirSrc);
        assertThatDirectory(zip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(zip, password).exists().root().matches(rootAssert);
    }

    public void shouldCreateNewZipWithSelectedFilesAndPkwareEncryption() throws IOException {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder()
                                                         .compression(Compression.DEFLATE, CompressionLevel.NORMAL)
                                                         .encryption(Encryption.PKWARE, password).build();
        ZipSettings settings = ZipSettings.builder()
                                          .entrySettingsProvider(fileName -> entrySettings)
                                          .comment("password: " + passwordStr).build();

        Path zip = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");

        ZipIt.zip(zip).settings(settings).add(filesDirCars);
        assertThatDirectory(zip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(zip, password).exists().root().hasDirectories(0).hasFiles(3);
        assertThatZipFile(zip, password).root().matches(dirCarsAssert);
    }

    public void shouldThrowExceptionWhenPkwareEncryptionAndEmptyPassword() throws IOException {
        assertThatThrownBy(() -> ZipEntrySettings.builder()
                                                 .compression(Compression.STORE, CompressionLevel.NORMAL)
                                                 .encryption(Encryption.PKWARE, null).build())
                .isExactlyInstanceOf(EmptyPasswordException.class);

        assertThatThrownBy(() -> ZipEntrySettings.builder()
                                                 .compression(Compression.STORE, CompressionLevel.NORMAL)
                                                 .encryption(Encryption.PKWARE, ArrayUtils.EMPTY_CHAR_ARRAY).build())
                .isExactlyInstanceOf(EmptyPasswordException.class);
    }

    public void shouldUnzipWhenStoreSolidPkware() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);

        UnzipIt.zip(zipStoreSolidPkware).destDir(destDir).password(password).extract();
        assertThatDirectory(destDir).matches(rootAssert);
    }

    public void shouldUnzipWhenStoreSplitPkware() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);

        UnzipIt.zip(zipStoreSplitPkware).destDir(destDir).password(password).extract();
        assertThatDirectory(destDir).matches(rootAssert);
    }

    public void shouldThrowExceptionWhenUnzipPkwareEncryptedZipWithIncorrectPassword() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);

        char[] password = UUID.randomUUID().toString().toCharArray();
        UnzipSettings settings = UnzipSettings.builder().password(password).build();

        assertThatThrownBy(() -> UnzipIt.zip(zipStoreSplitPkware).destDir(destDir).settings(settings).extract())
                .isExactlyInstanceOf(IncorrectPasswordException.class);
    }

    public void shouldUnzipWhenZip64ContainsOnlyOneCrcByteMatch() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        Path zip = Paths.get("src/test/resources/zip/zip64_crc1byte_check.zip").toAbsolutePath();

        UnzipIt.zip(zip).destDir(destDir).password("Shu1an@2019GTS".toCharArray()).extract();
        assertThatDirectory(destDir).exists().hasDirectories(0).hasFiles(1);
        assertThatDirectory(destDir).file("hello.txt").exists().hasSize(11).hasContent("hello,itsme");
    }

    public void shouldCreateSingleZipWithFilesWhenLzmaCompressionAndPkwareEncryption() throws IOException {
        ZipEntrySettings entrySettings = ZipEntrySettings.builder()
                                                         .compression(Compression.LZMA, CompressionLevel.NORMAL)
                                                         .encryption(Encryption.PKWARE, password)
                                                         .lzmaEosMarker(true).build();
        ZipSettings settings = ZipSettings.builder()
                                          .entrySettingsProvider(fileName -> entrySettings)
                                          .comment("password: " + passwordStr).build();

        Path zip = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");

        ZipIt.zip(zip).settings(settings).add(filesDirBikes);
        assertThatDirectory(zip.getParent()).exists().hasDirectories(0).hasFiles(1);
        assertThatZipFile(zip, password).root().matches(dirBikesAssert);
    }

}
