package ru.olegcherednik.zip4jvm.compatibility.sevenzip;

import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.UnzipIt;
import ru.olegcherednik.zip4jvm.Zip4jvmSuite;

import java.io.IOException;
import java.nio.file.Path;

import static ru.olegcherednik.zip4jvm.TestData.sevenZipLzmaSolidAesZip;
import static ru.olegcherednik.zip4jvm.TestData.sevenZipLzmaSolidZip;
import static ru.olegcherednik.zip4jvm.TestData.sevenZipStoreSolidPkwareZip;
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

    public void shouldUnzipWhenLzmaSolid() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        UnzipIt.zip(sevenZipLzmaSolidZip).destDir(destDir).extract();
        assertThatDirectory(destDir).matches(dirBikesAssert);
    }

    public void shouldUnzipWhenLzmaAndAesEncryption() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        UnzipIt.zip(sevenZipLzmaSolidAesZip).destDir(destDir).password(password).extract();
        assertThatDirectory(destDir).matches(dirBikesAssert);
    }

    public void shouldUnzipWhenLzmaAndPkwareEncryption() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        UnzipIt.zip(sevenZipStoreSolidPkwareZip).destDir(destDir).password(password).extract();
        assertThatDirectory(destDir).matches(dirBikesAssert);
    }

    public void shouldUnzipWhenSevenZipSplit() throws IOException {
        Path destDir = Zip4jvmSuite.subDirNameAsMethodName(rootDir);
        UnzipIt.zip(sevenZipStoreSplitZip).destDir(destDir).extract();
        assertThatDirectory(destDir).matches(rootAssert);
    }

}
