package ru.olegcherednik.zip4jvm.model;

import org.testng.annotations.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Oleg Cherednik
 * @since 28.09.2019
 */
@Test
public class CompressionTest {

    public void shouldParseCompressionMethodWhenSupportedMethod() {
        assertThat(Compression.parseCompressionMethod(CompressionMethod.STORE)).isSameAs(Compression.STORE);
        assertThat(Compression.parseCompressionMethod(CompressionMethod.DEFLATE)).isSameAs(Compression.DEFLATE);
    }

    public void shouldThrowExceptionWhenCompressionMethodNotSupported() {
        for (CompressionMethod method : CompressionMethod.values())
            if (method != CompressionMethod.STORE && method != CompressionMethod.DEFLATE && method != CompressionMethod.LZMA)
                assertThatThrownBy(() -> Compression.parseCompressionMethod(method)).isExactlyInstanceOf(EnumConstantNotPresentException.class);
    }
}
