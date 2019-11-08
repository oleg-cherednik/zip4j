package ru.olegcherednik.zip4jvm.encryption;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.UnzipIt;
import ru.olegcherednik.zip4jvm.Zip4jvmSuite;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static ru.olegcherednik.zip4jvm.Zip4jvmSuite.password;

/**
 * @author Oleg Cherednik
 * @since 08.11.2019
 */
@Test
@SuppressWarnings("FieldNamingConvention")
public class EncryptionStrongTest {

    private static final Path rootDir = Zip4jvmSuite.generateSubDirNameWithTime(EncryptionStrongTest.class);

    @BeforeClass
    public static void createDir() throws IOException {
        Files.createDirectories(rootDir);
    }

    @AfterClass(enabled = Zip4jvmSuite.clear)
    public static void removeDir() throws IOException {
        Zip4jvmSuite.removeDir(rootDir);
    }

    public void shouldEncryptCentralDirectory() throws IOException {
//        ZipEntrySettings entrySettings = ZipEntrySettings.builder().compression(Compression.STORE, CompressionLevel.NORMAL).build();
//        ZipSettings settings = ZipSettings.builder().entrySettings(entrySettings).encryptFileNames(true).build();

//        Path zip = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.zip");
//        ZipIt.zip(zip).settings(settings).add(fileOlegCherednik);


//        Path zip = Paths.get("d:/zip4jvm/securezip/strong.zip");
//        Path zip = Paths.get("d:/zip4jvm/securezip/strong_128.zip");
//        Path zip = Paths.get("d:/zip4jvm/securezip/threedes.zip");
        Path zip = Paths.get("d:/zip4jvm/securezip/strong_aes128.zip");
        UnzipIt.zip(zip).destDir(rootDir).password(password).extract();
    }
}
