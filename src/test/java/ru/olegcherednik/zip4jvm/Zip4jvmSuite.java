package ru.olegcherednik.zip4jvm;

import org.apache.commons.io.FileUtils;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import ru.olegcherednik.zip4jvm.data.DefalteZipData;
import ru.olegcherednik.zip4jvm.data.StoreZipData;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static ru.olegcherednik.zip4jvm.TestData.dirEmpty;
import static ru.olegcherednik.zip4jvm.TestData.dirRoot;
import static ru.olegcherednik.zip4jvm.TestData.dirSrc;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatDirectory;

/**
 * @author Oleg Cherednik
 * @since 23.03.2019
 */
@SuppressWarnings("FieldNamingConvention")
public class Zip4jvmSuite {

    /** Password for encrypted zip */
    public static final String passwordStr = "1";
    public static final char[] password = passwordStr.toCharArray();
    /** Clear resources */
    public static final boolean clear = false;

    public static final long SIZE_1MB = 1024 * 1024;

    private static final long time = System.currentTimeMillis();

    @BeforeSuite
    public void beforeSuite() throws IOException {
        removeDir(dirRoot);

        copyTestData();
        StoreZipData.createStoreZip();
        DefalteZipData.createDeflateZip();
    }

    @AfterSuite(enabled = clear)
    public void afterSuite() throws IOException {
        removeDir(dirRoot);
    }

    private static void copyTestData() throws IOException {
        Files.createDirectories(dirEmpty);

        Path dataDir = Paths.get("src/test/resources/data").toAbsolutePath();

        Files.walk(dataDir).forEach(path -> {
            try {
                if (Files.isDirectory(path))
                    Files.createDirectories(dirSrc.resolve(dataDir.relativize(path)));
                else if (Files.isRegularFile(path))
                    Files.copy(path, dirSrc.resolve(dataDir.relativize(path)));
            } catch(IOException e) {
                e.printStackTrace();
            }
        });

        assertThatDirectory(dirSrc).matches(TestDataAssert.dirSrcAssert);
    }

    public static void removeDir(Path path) throws IOException {
        if (Files.exists(path))
            FileUtils.deleteQuietly(path.toFile());
    }

    public static Path copy(Path rootDir, Path srcFile) throws IOException {
        Path zipFile = generateZipFileName(rootDir);
        Files.copy(srcFile, zipFile);
        return zipFile;
    }

    public static Path generateZipFileName(Path rootDir) {
        return rootDir.resolve("src_" + System.currentTimeMillis() + ".zip");
    }

    public static Path generateSubDirName(Class<?> cls) {
        return dirRoot.resolve(cls.getSimpleName());
    }

    public static Path generateSubDirNameWithTime(Class<?> cls) {
        String baseDir = Zip4jvmSuite.class.getPackage().getName();
        String[] parts = cls.getName().substring(baseDir.length() + 1).split("\\.");
        Path path = dirRoot;

        if (parts.length == 1)
            path = path.resolve(parts[0]).resolve(String.valueOf(time));
        else {
            for (int i = 0; i < parts.length; i++) {
                if (i == 1)
                    path = path.resolve(String.valueOf(time));

                path = path.resolve(parts[i]);
            }
        }

        return path;
    }

    public static Path subDirNameAsMethodNameWithTme(Path rootDir) {
        return rootDir.resolve(TestDataAssert.getMethodName()).resolve(Paths.get(String.valueOf(time)));
    }

    public static Path subDirNameAsMethodName(Path rootDir) {
        return rootDir.resolve(TestDataAssert.getMethodName());
    }

    public static Path subDirNameAsRelativePathToRoot(Path rootDir, Path zipFile) {
        Path path;

        if (zipFile.toAbsolutePath().toString().contains("resources"))
            path = Paths.get("src/test/resources/winrar").toAbsolutePath().relativize(zipFile);
        else
            path = dirRoot.relativize(zipFile);

        String dirName = path.toString().replaceAll("\\\\", "_");

        return rootDir.resolve(dirName);
    }

}