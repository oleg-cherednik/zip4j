package ru.olegcherednik.zip4jvm.compatibility;

import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.UnzipIt;
import ru.olegcherednik.zip4jvm.Zip4jvmSuite;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;

import static ru.olegcherednik.zip4jvm.TestData.sevenZipLzmaSolidAesZip;
import static ru.olegcherednik.zip4jvm.TestData.sevenZipLzmaSolidZip;
import static ru.olegcherednik.zip4jvm.TestData.sevenZipStoreSplitZip;
import static ru.olegcherednik.zip4jvm.TestDataAssert.dirBikesAssert;
import static ru.olegcherednik.zip4jvm.TestDataAssert.rootAssert;
import static ru.olegcherednik.zip4jvm.Zip4jvmSuite.password;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatDirectory;

/**
 * @author Oleg Cherednik
 * @since 25.01.2020
 */
@Test
@SuppressWarnings({ "FieldNamingConvention", "NewClassNamingConvention" })
public class SevenZipToZip4jvmCompatibilityTest {

    private static final Path rootDir = Zip4jvmSuite.generateSubDirNameWithTime(SevenZipToZip4jvmCompatibilityTest.class);

    public void shouldUnzipWhenSevenZipSplit() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        UnzipIt.zip(sevenZipStoreSplitZip).destDir(destDir).extract();
        assertThatDirectory(destDir).matches(rootAssert);
    }

    public void checkCompatibilityWithLzmaSevenZip() throws IOException {
        Path dir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);

        for (Path zip : Arrays.asList(sevenZipLzmaSolidZip, sevenZipLzmaSolidAesZip)) {
            Path destDir = Zip4jvmSuite.subDirNameAsRelativePathToRoot(dir, zip);
            UnzipIt.zip(zip).destDir(destDir).password(password).extract();
            assertThatDirectory(destDir).matches(dirBikesAssert);
        }
    }

}
