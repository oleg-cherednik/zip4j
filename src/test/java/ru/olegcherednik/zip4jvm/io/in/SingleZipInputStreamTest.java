package ru.olegcherednik.zip4jvm.io.in;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.Zip4jvmSuite;
import ru.olegcherednik.zip4jvm.io.in.data.SingleZipInputStream;
import ru.olegcherednik.zip4jvm.io.in.file.SrcFile;
import ru.olegcherednik.zip4jvm.model.Charsets;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * @author Oleg Cherednik
 * @since 28.09.2019
 */
@Test
@SuppressWarnings("FieldNamingConvention")
public class SingleZipInputStreamTest {

    private static final Path rootDir = Zip4jvmSuite.generateSubDirNameWithTime(SingleZipInputStreamTest.class);

    @BeforeClass
    public static void createDir() throws IOException {
        Files.createDirectories(rootDir);
    }

    @AfterClass(enabled = Zip4jvmSuite.clear)
    public static void removeDir() throws IOException {
        Zip4jvmSuite.removeDir(rootDir);
    }

    public void shouldReadStreamWhenUsingDataInput() throws IOException {
        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.data");
        FileUtils.writeByteArrayToFile(file.toFile(), new byte[] { 0x1, 0x2 }, true);
        FileUtils.writeByteArrayToFile(file.toFile(), new byte[] { 0x3, 0x4, 0x5, 0x6 }, true);
        FileUtils.writeByteArrayToFile(file.toFile(), new byte[] { 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE }, true);
        FileUtils.writeByteArrayToFile(file.toFile(), new byte[] { 0xF, 0x10 }, true);
        FileUtils.writeStringToFile(file.toFile(), "oleg", Charsets.UTF_8, true);
        FileUtils.writeByteArrayToFile(file.toFile(), new byte[] { 0x11 }, true);
        FileUtils.writeByteArrayToFile(file.toFile(), new byte[] { 0x12, 0x13, 0x14 }, true);

        try (SingleZipInputStream in = new SingleZipInputStream(SrcFile.of(file))) {
            assertThat(in.getOffs()).isEqualTo(0);

            assertThat(in.readWord()).isEqualTo(0x201);
            assertThat(in.getOffs()).isEqualTo(2);

            assertThat(in.readDword()).isEqualTo(0x06050403);
            assertThat(in.getOffs()).isEqualTo(6);

            assertThat(in.readQword()).isEqualTo(0x0E0D0C0B0A090807L);
            assertThat(in.getOffs()).isEqualTo(14);
            assertThat(in.toString()).isEqualTo("offs: 14 (0xe)");

            in.skip(2);
            assertThat(in.getOffs()).isEqualTo(16);

            assertThat(in.readString(4, Charsets.UTF_8)).isEqualTo("oleg");
            assertThat(in.getOffs()).isEqualTo(20);

            assertThat(in.readByte()).isEqualTo(0x11);
            assertThat(in.getOffs()).isEqualTo(21);

            assertThat(in.readBytes(3)).isEqualTo(new byte[] { 0x12, 0x13, 0x14 });
            assertThat(in.getOffs()).isEqualTo(24);

            assertThat(in.getOffs()).isEqualTo(in.length());
        }
    }

    public void shouldIgnoreSkipWhenZeroOrNegative() throws IOException {
        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.data");
        FileUtils.writeByteArrayToFile(file.toFile(), new byte[] { 0x1, 0x2 }, true);

        try (SingleZipInputStream in = new SingleZipInputStream(SrcFile.of(file))) {
            assertThat(in.getOffs()).isEqualTo(0);

            assertThatCode(() -> in.skip(-1)).doesNotThrowAnyException();
            assertThatCode(() -> in.skip(0)).doesNotThrowAnyException();
            assertThat(in.getOffs()).isEqualTo(0);
        }
    }

    public void shouldRetrieveAllBytesWhenReadTooManyBytes() throws IOException {
        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.data");
        FileUtils.writeByteArrayToFile(file.toFile(), new byte[] { 0x1, 0x2 }, true);

        try (SingleZipInputStream in = new SingleZipInputStream(SrcFile.of(file))) {
            assertThat(in.readBytes(3)).isEqualTo(new byte[] { 0x1, 0x2 });
            assertThat(in.getOffs()).isEqualTo(2);
        }
    }

    public void shouldRetrieveNegativeOffsWhenCannotGetFilePointer() throws IOException {
        Path file = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("src.data");
        FileUtils.writeByteArrayToFile(file.toFile(), new byte[] { 0x1, 0x2 }, true);

        SingleZipInputStream in = new SingleZipInputStream(SrcFile.of(file));
        assertThat(in.getOffs()).isEqualTo(0);

        in.close();
        assertThatCode(in::getOffs).doesNotThrowAnyException();
        assertThat(in.getOffs()).isEqualTo(IOUtils.EOF);
    }

}
