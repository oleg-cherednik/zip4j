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

import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatFile;

/**
 * @author Oleg Cherednik
 * @since 08.02.2021
 */
@Test
@SuppressWarnings("FieldNamingConvention")
public class ZipInfoPrintShortInfoTest {

    private static final Path rootDir = Zip4jvmSuite.generateSubDirNameWithTime(ZipInfoPrintShortInfoTest.class);

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
            ZipInfo.zip(TestData.zipStoreSplitAes).printShortInfo();
        }

        assertThatFile(file).matchesResourceLines("/info/store_split_aes.txt");
    }

    public void shouldRetrieveInfoWhenStoreSolidAesStrong() throws IOException {
        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("actual.txt");
        Files.createDirectories(file.getParent());

        try (PrintStream out = new PrintStream(file.toFile())) {
            ZipInfo.zip(TestData.secureZipStoreSolidAesStringZip).printShortInfo(out);
        }

        assertThatFile(file).matchesResourceLines("/info/store_solid_aes_strong.txt");
    }

    private static ZipInfo zipInfo() {
        Path path = Paths.get("d:/zip4jvm/tmp/aes.zip");
//        Files.deleteIfExists(path);

//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/tmp/lzma/lzma_16mb.zip"));
//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/tmp/lzma/lzma_1mb_32.zip"));
//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/tmp/lzma/enc/lzma-ultra.zip"));
//        res = res.settings(ZipInfoSettings.builder().readEntries(false).build());
//        ZipInfo res = ZipInfo.zip(sevenZipLzmaSolidZip);
//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/3des/3des_store_168.zip"));
//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/bzip2/bzip2.zip"));
//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/bzip2/min.zip"));
//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/ZIpCrypto/src.zip"));
        ZipInfo res = ZipInfo.zip(Paths.get("d:/Programming/GitHub/zip4jvm/src/test/resources/secure-zip/store_solid_aes_strong.zip"));

//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/securezip/aes/aes128.zip"));
//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/securezip/aes/aes192.zip"));
//        ZipInfo res = ZipInfo.zip(Paths.get("d:/zip4jvm/securezip/aes/aes256.zip"));
//        ZipInfo res = ZipInfo.zip(Paths.get("D:\\zip4jvm\\foo\\compression\\1581465466689\\CompressionLzmaTest\\shouldCreateSingleZipWithFilesWhenLzmaCompressionAndAesEncryption/src.zip"));
//        ZipInfo res = ZipInfo.zip(
//                Paths.get("D:\\zip4jvm\\foo\\encryption\\1581466463189\\EncryptionAesTest\\shouldCreateNewZipWithFolderAndAes256Encryption/src.zip"));

        return res;
    }

    @Test//(enabled = false)
    public void printShortInfo() throws IOException {
        ZipInfoSettings settings = ZipInfoSettings.builder().copyPayload(true).build();
        zipInfo().settings(settings).printShortInfo(System.out);
    }

}
