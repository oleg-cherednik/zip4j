package ru.olegcherednik.zip4jvm.view;

import org.apache.commons.lang.ArrayUtils;
import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.Zip4jvmSuite;

import java.io.IOException;
import java.io.PrintStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * @author Oleg Cherednik
 * @since 17.12.2019
 */
@Test
public class ByteArrayHexViewTest {

    public void shouldPrintOneLineWhenLessThanColumnWidth() throws IOException {
        byte[] data = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF };

        String[] lines = Zip4jvmSuite.execute(new ByteArrayHexView(data, 4, 52));
        assertThat(lines).hasSize(1);
        assertThat(lines[0]).isEqualTo("    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
    }

    public void shouldPrintMoreThanOneLineWhenMoreThanColumnWidth() throws IOException {
        byte[] data = { 0x64, 0x75, 0x63, 0x61, 0x74, 0x69, 0x2D, 0x70, 0x61, 0x6E, 0x69, 0x67, 0x61, 0x6C, 0x65, 0x2D, 0x31, 0x31, 0x39, 0x39, 0x2E,
                0x6A, 0x70, 0x67 };

        String[] lines = Zip4jvmSuite.execute(new ByteArrayHexView(data, 4, 52));
        assertThat(lines).hasSize(2);
        assertThat(lines[0]).isEqualTo("    64 75 63 61 74 69 2D 70 61 6E 69 67 61 6C 65 2D");
        assertThat(lines[1]).isEqualTo("    31 31 39 39 2E 6A 70 67");
    }

    public void shouldFillWholeColumnWhenColumnWidthNotStandard() throws IOException {
        byte[] data = { 0x64, 0x75, 0x63, 0x61, 0x74, 0x69, 0x2D, 0x70, 0x61, 0x6E, 0x69, 0x67, 0x61, 0x6C, 0x65, 0x2D, 0x31, 0x31, 0x39, 0x39, 0x2E,
                0x6A, 0x70, 0x67 };

        String[] lines = Zip4jvmSuite.execute(new ByteArrayHexView(data, 4, 70));
        assertThat(lines).hasSize(2);
        assertThat(lines[0]).isEqualTo("    64 75 63 61 74 69 2D 70 61 6E 69 67 61 6C 65 2D 31 31 39 39 2E 6A");
        assertThat(lines[1]).isEqualTo("    70 67");
    }

    public void shouldRetrieveFalseWhenDataEmpty() {
        PrintStream out = mock(PrintStream.class);
        assertThat(new ByteArrayHexView(null, 4, 52).print(out)).isFalse();
        assertThat(new ByteArrayHexView(ArrayUtils.EMPTY_BYTE_ARRAY, 4, 52).print(out)).isFalse();
    }

}
