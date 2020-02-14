package ru.olegcherednik.zip4jvm.view;

import org.testng.annotations.Test;
import ru.olegcherednik.zip4jvm.Zip4jvmSuite;
import ru.olegcherednik.zip4jvm.model.CompressionLevel;
import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.model.GeneralPurposeFlag;
import ru.olegcherednik.zip4jvm.model.ShannonFanoTreesNumber;
import ru.olegcherednik.zip4jvm.model.SlidingDictionarySize;

import java.io.IOException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * @author Oleg Cherednik
 * @since 05.11.2019
 */
@Test
public class CompressionMethodViewTest {

    public void shouldRetrieveCompressionMethodTitleWhenSingleLine() throws IOException {
        String[] lines = Zip4jvmSuite.execute(new CompressionMethodView(CompressionMethod.STORE, new GeneralPurposeFlag(), 0, 52));
        assertThat(lines).hasSize(1);
        assertThat(lines[0]).isEqualTo("compression method (00):                            none (stored)");
    }

    public void shouldRetrieveThreeLinesWhenFileImplodedMethod() throws IOException {
        GeneralPurposeFlag generalPurposeFlag = new GeneralPurposeFlag();
        generalPurposeFlag.setSlidingDictionarySize(SlidingDictionarySize.SD_4K);
        generalPurposeFlag.setShannonFanoTreesNumber(ShannonFanoTreesNumber.THREE);

        String[] lines = Zip4jvmSuite.execute(new CompressionMethodView(CompressionMethod.FILE_IMPLODED, generalPurposeFlag, 0, 52));
        assertThat(lines).hasSize(3);
        assertThat(lines[0]).isEqualTo("compression method (06):                            imploded");
        assertThat(lines[1]).isEqualTo("  size of sliding dictionary (implosion):           4K");
        assertThat(lines[2]).isEqualTo("  number of Shannon-Fano trees (implosion):         3");
    }

    public void shouldRetrieveTwoLinesWhenLzmaMethod() throws IOException {
        for (boolean eosMarker : Arrays.asList(true, false)) {
            GeneralPurposeFlag generalPurposeFlag = new GeneralPurposeFlag();
            generalPurposeFlag.setLzmaEosMarker(eosMarker);

            String[] lines = Zip4jvmSuite.execute(new CompressionMethodView(CompressionMethod.LZMA, generalPurposeFlag, 0, 52));
            assertThat(lines).hasSize(2);
            assertThat(lines[0]).isEqualTo("compression method (14):                            lzma encoding");
            assertThat(lines[1]).isEqualTo("  end-of-stream (EOS) marker:                       " + (eosMarker ? "yes" : "no"));
        }
    }

    public void shouldRetrieveCompressionSubTypeWhenDeflateCompressionMethod() throws IOException {
        GeneralPurposeFlag generalPurposeFlag = new GeneralPurposeFlag();
        generalPurposeFlag.setCompressionLevel(CompressionLevel.NORMAL);

        for (CompressionMethod compressionMethod : Arrays.asList(CompressionMethod.DEFLATE, CompressionMethod.ENHANCED_DEFLATE)) {
            String[] lines = Zip4jvmSuite.execute(new CompressionMethodView(compressionMethod, generalPurposeFlag, 0, 52));
            assertThat(lines).hasSize(2);

            if (compressionMethod == CompressionMethod.DEFLATE)
                assertThat(lines[0]).isEqualTo("compression method (08):                            deflated");
            else if (compressionMethod == CompressionMethod.ENHANCED_DEFLATE)
                assertThat(lines[0]).isEqualTo("compression method (09):                            deflated (enhanced)");

            assertThat(lines[1]).isEqualTo("  compression sub-type (deflation):                 normal");
        }
    }

    public void shouldThrowIllegalArgumentExceptionWhenNameBlank() {
        assertThatThrownBy(() -> new CompressionMethodView(null, mock(GeneralPurposeFlag.class), 0, 54))
                .isExactlyInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CompressionMethodView(CompressionMethod.DEFLATE, null, 0, 54))
                .isExactlyInstanceOf(IllegalArgumentException.class);
    }

}
