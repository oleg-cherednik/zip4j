package ru.olegcherednik.zip4jvm.model;

import org.mockito.InOrder;
import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Oleg Cherednik
 * @since 01.10.2019
 */
@Test
public class ExtraFieldTest {

    public void shouldRetrieveNullObjectWhenBuildEmptyExtraField() {
        assertThat(ExtraField.builder().build()).isSameAs(ExtraField.NULL);
    }

    public void shouldIgnoreNullOrNullObjectRecordWhenBuildExtraField() {
        assertThat(ExtraField.builder().addRecord((ExtraField.Record)null).build()).isSameAs(ExtraField.NULL);
        assertThat(ExtraField.builder().build()).isSameAs(ExtraField.NULL);
        assertThat(ExtraField.builder().addRecord(Zip64.ExtendedInfo.NULL).build()).isSameAs(ExtraField.NULL);
    }

    public void shouldRetrieveCorrectStringWhenToString() {
        ExtraField.Record record = mock(ExtraField.Record.class);
        when(record.isNull()).thenReturn(false);
        when(record.getSignature()).thenReturn(666);

        ExtraField extraField = ExtraField.builder().addRecord(record).build();
        assertThat(extraField).isNotSameAs(ExtraField.NULL);

        assertThat(ExtraField.NULL.toString()).isEqualTo("<null>");
        assertThat(extraField.toString()).isEqualTo("total: 1");
    }

    public void shouldRetrievePredefinedBlockSizeWhenUnknownRecord() {
        ExtraField.Record record = new ExtraField.Record.Unknown(777, new byte[] { 0xA, 0xB, 0xC });
        assertThat(record.getBlockSize()).isEqualTo(3);
    }

    public void shouldWritePredefinedDataWhenUnknownRecord() throws IOException {
        DataOutput out = mock(DataOutput.class);
        InOrder order = inOrder(out);

        ExtraField.Record record = new ExtraField.Record.Unknown(777, new byte[] { 0xA, 0xB, 0xC });
        record.write(out);

        order.verify(out).writeWordSignature(eq(777));
        order.verify(out).writeWord(eq(3));
        order.verify(out).write(eq(new byte[] { 0xA, 0xB, 0xC }), eq(0), eq(3));
    }

}
