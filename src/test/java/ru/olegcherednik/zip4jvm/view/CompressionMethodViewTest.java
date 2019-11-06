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

/**
 * @author Oleg Cherednik
 * @since 05.11.2019
 */
@Test
public class CompressionMethodViewTest {

    public void shouldRetrieveCompressionMethodTitleWhenSingleLine() throws IOException {
        String[] lines = Zip4jvmSuite.execute(CompressionMethodView.builder()
                                                                   .compressionMethod(CompressionMethod.STORE)
                                                                   .generalPurposeFlag(new GeneralPurposeFlag())
                                                                   .offs(0)
                                                                   .columnWidth(52).build());
        assertThat(lines).hasSize(1);
        assertThat(lines[0]).isEqualTo("compression method (00):                            none (stored)");
    }

    public void shouldRetrieveThreeLinesWhenFileImplodedMethod() throws IOException {
        GeneralPurposeFlag generalPurposeFlag = new GeneralPurposeFlag();
        generalPurposeFlag.setSlidingDictionarySize(SlidingDictionarySize.SD_4K);
        generalPurposeFlag.setShannonFanoTreesNumber(ShannonFanoTreesNumber.THREE);

        String[] lines = Zip4jvmSuite.execute(CompressionMethodView.builder()
                                                                   .compressionMethod(CompressionMethod.FILE_IMPLODED)
                                                                   .generalPurposeFlag(generalPurposeFlag)
                                                                   .offs(0)
                                                                   .columnWidth(52).build());
        assertThat(lines).hasSize(3);
        assertThat(lines[0]).isEqualTo("compression method (06):                            imploded");
        assertThat(lines[1]).isEqualTo("  size of sliding dictionary (implosion):           4K");
        assertThat(lines[2]).isEqualTo("  number of Shannon-Fano trees (implosion):         3");
    }

    public void shouldRetrieveTwoLinesWhenLzmaMethod() throws IOException {
        for (boolean eosMarker : Arrays.asList(true, false)) {
            GeneralPurposeFlag generalPurposeFlag = new GeneralPurposeFlag();
            generalPurposeFlag.setEosMarker(eosMarker);

            String[] lines = Zip4jvmSuite.execute(CompressionMethodView.builder()
                                                                       .compressionMethod(CompressionMethod.LZMA)
                                                                       .generalPurposeFlag(generalPurposeFlag)
                                                                       .offs(0)
                                                                       .columnWidth(52).build());
            assertThat(lines).hasSize(2);
            assertThat(lines[0]).isEqualTo("compression method (14):                            lzma encoding");
            assertThat(lines[1]).isEqualTo("  end-of-stream (EOS) marker:                       " + (eosMarker ? "yes" : "no"));
        }
    }

    public void shouldRetrieveCompressionSubTypeWhenDeflateCompressionMethod() throws IOException {
        GeneralPurposeFlag generalPurposeFlag = new GeneralPurposeFlag();
        generalPurposeFlag.setCompressionLevel(CompressionLevel.NORMAL);

        for (CompressionMethod compressionMethod : Arrays.asList(CompressionMethod.DEFLATE, CompressionMethod.FILE_ENHANCED_DEFLATED)) {
            String[] lines = Zip4jvmSuite.execute(CompressionMethodView.builder()
                                                                       .compressionMethod(compressionMethod)
                                                                       .generalPurposeFlag(generalPurposeFlag)
                                                                       .offs(0)
                                                                       .columnWidth(52).build());
            assertThat(lines).hasSize(2);

            if (compressionMethod == CompressionMethod.DEFLATE)
                assertThat(lines[0]).isEqualTo("compression method (08):                            deflated");
            else if (compressionMethod == CompressionMethod.FILE_ENHANCED_DEFLATED)
                assertThat(lines[0]).isEqualTo("compression method (09):                            deflated (enhanced)");

            assertThat(lines[1]).isEqualTo("  compression sub-type (deflation):                 normal");
        }
    }

}
