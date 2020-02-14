package ru.olegcherednik.zip4jvm.model;

import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Oleg Cherednik
 * @since 01.10.2019
 */
@Test
@SuppressWarnings("NewClassNamingConvention")
public class Zip64Test {

    public void shouldRetrieveNullObjectWhenOneOfArgumentsIsNull() {
        Zip64.EndCentralDirectoryLocator endCentralDirectoryLocator = new Zip64.EndCentralDirectoryLocator();
        Zip64.EndCentralDirectory endCentralDirectory = new Zip64.EndCentralDirectory();

        assertThat(Zip64.of(null, null)).isSameAs(Zip64.NULL);
        assertThat(Zip64.of(endCentralDirectoryLocator, null)).isSameAs(Zip64.NULL);
        assertThat(Zip64.of(null, endCentralDirectory)).isSameAs(Zip64.NULL);
        assertThat(Zip64.of(endCentralDirectoryLocator, endCentralDirectory)).isNotSameAs(Zip64.NULL);
    }

    public void shouldRetrieveSpecialStringForNullObjectWhenToString() {
        Zip64 zip64 = Zip64.of(new Zip64.EndCentralDirectoryLocator(), new Zip64.EndCentralDirectory());
        assertThat(zip64.toString()).isNotEqualTo("<null>");
        assertThat(Zip64.NULL.toString()).isEqualTo("<null>");
    }

    public void shouldRetrieveZeroWhenGetSizeNullObject() {
        assertThat(Zip64.ExtendedInfo.NULL.getDataSize()).isZero();
        assertThat(Zip64.ExtendedInfo.NULL.getBlockSize()).isZero();
    }

    public void shouldRetrieveCorrectStringWhenToString() {
        assertThat(Zip64.ExtendedInfo.NULL.toString()).isEqualTo("<null>");
        assertThat(Zip64.ExtendedInfo.builder().disk(1).build().toString()).isNotEqualTo("<null>");
    }

    public void shouldRetrieveNullObjectWhenAllDataInExtendedInfoNoExist() {
        assertThat(Zip64.ExtendedInfo.builder().build()).isSameAs(Zip64.ExtendedInfo.NULL);
    }

    public void shouldIgnoreWriteOutputWhenNullObject() throws IOException {
        DataOutput out = mock(DataOutput.class);

        Zip64.ExtendedInfo.NULL.write(out);

        verify(out, never()).writeWordSignature(any(int.class));
    }

    public void shouldIgnoreDataWhenNotExists() throws IOException {
        DataOutput out = mock(DataOutput.class);

        Zip64.ExtendedInfo.builder().uncompressedSize(1).build().write(out);
        verify(out, times(1)).writeQword(eq(1L));
        verify(out, never()).writeDword(any(long.class));
        reset(out);

        Zip64.ExtendedInfo.builder().compressedSize(2).build().write(out);
        verify(out, times(1)).writeQword(eq(2L));
        verify(out, never()).writeDword(any(long.class));
        reset(out);

        Zip64.ExtendedInfo.builder().localFileHeaderOffs(3).build().write(out);
        verify(out, times(1)).writeQword(eq(3L));
        verify(out, never()).writeDword(any(long.class));
        reset(out);

        Zip64.ExtendedInfo.builder().disk(4).build().write(out);
        verify(out, never()).writeQword(any(long.class));
        verify(out, times(1)).writeDword(eq(4L));
        reset(out);
    }
}
