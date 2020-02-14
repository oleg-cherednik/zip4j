package ru.olegcherednik.zip4jvm.model;

import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.crypto.aes.AesStrength;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * @author Oleg Cherednik
 * @since 25.09.2019
 */
@Test
public class AesExtraFieldRecordTest {

    public void shouldCreateRecordWhenAllDataValid() {
        AesExtraFieldRecord record = AesExtraFieldRecord.builder()
                                                        .dataSize(7)
                                                        .vendor("AE")
                                                        .versionNumber(2)
                                                        .strength(AesStrength.S256)
                                                        .compressionMethod(CompressionMethod.AES).build();

        assertThat(record).isNotNull();
        assertThat(record).isNotSameAs(AesExtraFieldRecord.NULL);
        assertThat(record.getDataSize()).isEqualTo(7);
        assertThat(record.getVendor()).isEqualTo("AE");
        assertThat(record.getVendor(Charsets.UTF_8)).isEqualTo(new byte[] { 0x41, 0x45 });
        assertThat(record.getVersionNumber()).isEqualTo(2);
        assertThat(record.getStrength()).isSameAs(AesStrength.S256);
        assertThat(record.getCompressionMethod()).isSameAs(CompressionMethod.AES);
    }

    public void shouldRetrieveNullStringWhenToStringForNullObject() {
        AesExtraFieldRecord record = AesExtraFieldRecord.builder()
                                                        .dataSize(7)
                                                        .vendor("AE")
                                                        .versionNumber(2)
                                                        .strength(AesStrength.S256)
                                                        .compressionMethod(CompressionMethod.AES).build();

        assertThat(record.toString()).isNotEqualTo("<null>");
        assertThat(AesExtraFieldRecord.NULL.toString()).isEqualTo("<null>");
    }

    public void shouldThrowExceptionWhenSetVendorMoreThan2CharactersLength() {
        assertThatThrownBy(() -> AesExtraFieldRecord.builder().vendor("AEAE")).isExactlyInstanceOf(Zip4jvmException.class);
    }

    public void shouldRetrieveNullWhenGetVendorWithGivenCharset() {
        AesExtraFieldRecord record = AesExtraFieldRecord.builder()
                                                        .dataSize(7)
                                                        .versionNumber(2)
                                                        .strength(AesStrength.S256)
                                                        .compressionMethod(CompressionMethod.AES).build();
        assertThat(record.getVendor(Charsets.UTF_8)).isNull();
    }

    public void shouldRetrieve0WhenGetBlockSizeForNullObject() {
        AesExtraFieldRecord record = AesExtraFieldRecord.builder()
                                                        .dataSize(7)
                                                        .versionNumber(2)
                                                        .strength(AesStrength.S256)
                                                        .compressionMethod(CompressionMethod.AES).build();

        assertThat(record).isNotSameAs(AesExtraFieldRecord.NULL);
        assertThat(record.getBlockSize()).isEqualTo(AesExtraFieldRecord.SIZE);
        assertThat(AesExtraFieldRecord.NULL.getBlockSize()).isEqualTo(0);
    }

    public void shouldIgnoreWriteWhenNullObject() throws IOException {
        DataOutput out = mock(DataOutput.class);

        AesExtraFieldRecord.NULL.write(out);

        verify(out, never()).writeWord(any(int.class));
        verify(out, never()).write(any(), any(int.class), any(int.class));
    }

}
