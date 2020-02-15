package ru.olegcherednik.zip4jvm;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.model.settings.ZipInfoSettings;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatDirectory;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatFile;

/**
 * @author Oleg Cherednik
 * @since 11.10.2019
 */
@Test
@SuppressWarnings("FieldNamingConvention")
public class ZipInfoTest {

    private static final Path rootDir = Zip4jvmSuite.generateSubDirNameWithTime(ZipInfoTest.class);

    @BeforeClass
    public static void createDir() throws IOException {
        Files.createDirectories(rootDir);
    }

    @AfterClass(enabled = Zip4jvmSuite.clear)
    public static void removeDir() throws IOException {
        Zip4jvmSuite.removeDir(rootDir);
    }

    public void shouldRetrieveInfoWhenStoreSolid() throws IOException {
        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("actual.txt");
        Files.createDirectories(file.getParent());

        try (PrintStream out = new PrintStream(file.toFile())) {
            ZipInfo.zip(TestData.zipStoreSolid).printShortInfo(out);
        }

        assertThatFile(file).matchesResourceLines("/info/store_solid.txt");
    }

    public void shouldRetrieveInfoWhenStoreSolidPkware() throws IOException {
        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("actual.txt");
        Files.createDirectories(file.getParent());

        try (PrintStream out = new PrintStream(file.toFile())) {
            ZipInfo.zip(TestData.zipStoreSolidPkware).printShortInfo(out);
        }

        assertThatFile(file).matchesResourceLines("/info/store_solid_pkware.txt");
    }

    public void shouldRetrieveInfoWhenStoreSolidAes() throws IOException {
        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("actual.txt");
        Files.createDirectories(file.getParent());

        try (PrintStream out = new PrintStream(file.toFile())) {
            ZipInfo.zip(TestData.zipStoreSolidAes).printShortInfo(out);
        }

        assertThatFile(file).matchesResourceLines("/info/store_solid_aes.txt");
    }

    public void shouldRetrieveInfoWhenStoreSplit() throws IOException {
        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("actual.txt");
        Files.createDirectories(file.getParent());

        try (PrintStream out = new PrintStream(file.toFile())) {
            ZipInfo.zip(TestData.zipStoreSplit).printShortInfo(out);
        }

        assertThatFile(file).matchesResourceLines("/info/store_split.txt");
    }

    public void shouldRetrieveInfoWhenStoreSplitPkware() throws IOException {
        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("actual.txt");
        Files.createDirectories(file.getParent());

        try (PrintStream out = new PrintStream(file.toFile())) {
            ZipInfo.zip(TestData.zipStoreSplitPkware).printShortInfo(out);
        }

        assertThatFile(file).matchesResourceLines("/info/store_split_pkware.txt");
    }

    public void shouldRetrieveInfoWhenStoreSplitAes() throws IOException {
        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("actual.txt");
        Files.createDirectories(file.getParent());

        try (PrintStream out = new PrintStream(file.toFile())) {
            ZipInfo.zip(TestData.zipStoreSplitAes).printShortInfo(out);
        }

        assertThatFile(file).matchesResourceLines("/info/store_split_aes.txt");
    }

    public void shouldDecomposeWhenStoreSolid() throws IOException {
        Path dir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        Files.createDirectories(dir.getParent());
        ZipInfo.zip(TestData.zipStoreSolid).decompose(dir);
        assertThatDirectory(dir).matchesResourceDirectory("/decompose/store_solid");
    }

    public void shouldDecomposeWhenStoreSolidPkware() throws IOException {
        Path dir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        Files.createDirectories(dir.getParent());
        ZipInfo.zip(TestData.zipStoreSolidPkware).decompose(dir);
        assertThatDirectory(dir).matchesResourceDirectory("/decompose/store_solid_pkware");
    }

    public void shouldDecomposeWhenStoreSolidAes() throws IOException {
        Path dir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        Files.createDirectories(dir.getParent());
        ZipInfo.zip(TestData.zipStoreSolidAes).decompose(dir);
        assertThatDirectory(dir).matchesResourceDirectory("/decompose/store_solid_aes");
    }

    public void shouldDecomposeWhenStoreSplit() throws IOException {
        Path dir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        Files.createDirectories(dir.getParent());
        ZipInfo.zip(TestData.zipStoreSplit).decompose(dir);
        assertThatDirectory(dir).matchesResourceDirectory("/decompose/store_split");
    }

    public void shouldDecomposeWhenStoreSplitPkware() throws IOException {
        Path dir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        Files.createDirectories(dir.getParent());
        ZipInfo.zip(TestData.zipStoreSplitPkware).decompose(dir);
        assertThatDirectory(dir).matchesResourceDirectory("/decompose/store_split_pkware");
    }

    public void shouldDecomposeWhenStoreSplitAes() throws IOException {
        Path dir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        Files.createDirectories(dir.getParent());
        ZipInfo.zip(TestData.zipStoreSplitAes).decompose(dir);
        assertThatDirectory(dir).matchesResourceDirectory("/decompose/store_split_aes");
    }

    private static ZipInfo zipInfo() {
        Path path = Paths.get("d:/zip4jvm/tmp/aes.zip");
//        Files.deleteIfExists(path);

//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/tmp/lzma/lzma_16mb.zip"));
//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/tmp/lzma/lzma_1mb_32.zip"));
//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/tmp/lzma/enc/lzma-ultra.zip"));
//        res = res.settings(ZipInfoSettings.builder().readEntries(false).build());
//        ZipInfo res = ZipInfo.zip(sevenZipLzmaSolidZip);
//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/securezip/aes128.zip"));
        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/securezip/3des168.zip"));
//        ZipInfo res = ZipInfo.zip(Paths.get("D:\\zip4jvm\\foo\\compression\\1581465466689\\CompressionLzmaTest\\shouldCreateSingleZipWithFilesWhenLzmaCompressionAndAesEncryption/src.zip"));
//        ZipInfo res = ZipInfo.zip(
//                Paths.get("D:\\zip4jvm\\foo\\encryption\\1581466463189\\EncryptionAesTest\\shouldCreateNewZipWithFolderAndAes256Encryption/src.zip"));

        return res;
    }

    @Test//(enabled = false)
    public void printShortInfo() throws IOException {
        zipInfo().printShortInfo(System.out);
    }

    @Test(enabled = false)
    public void decompose() throws IOException {
        zipInfo().settings(ZipInfoSettings.builder().copyPayload(true).build()).decompose(Zip4jvmSuite.subDirNameAsMethodName(rootDir));
    }

}
