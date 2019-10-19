package ru.olegcherednik.zip4jvm.view;

import lombok.Builder;
import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.model.GeneralPurposeFlag;

import java.io.PrintStream;

/**
 * @author Oleg Cherednik
 * @since 15.10.2019
 */
@Builder
public class CompressionMethodView {

    private final CompressionMethod compressionMethod;
    private final GeneralPurposeFlag generalPurposeFlag;
    private final String prefix;

    public void print(PrintStream out) {
        out.format("%-52s%s\n", String.format("%scompression method (%02d):", prefix, compressionMethod.getCode()), compressionMethod.getTitle());

        if (compressionMethod == CompressionMethod.FILE_IMPLODED) {
            out.format("%-52s%s\n", String.format("%s  size of sliding dictionary (implosion):", prefix),
                    generalPurposeFlag.getSlidingDictionarySize().getTitle());
            out.format("%-52s%s\n", String.format("%s  number of Shannon-Fano trees (implosion):", prefix),
                    generalPurposeFlag.getShannonFanoTreesNumber().getTitle());
        } else if (compressionMethod == CompressionMethod.DEFLATE || compressionMethod == CompressionMethod.FILE_ENHANCED_DEFLATED)
            out.format("%-52s%s\n", String.format("%s  compression sub-type (deflation):", prefix),
                    generalPurposeFlag.getCompressionLevel().getTitle());
        else if (compressionMethod == CompressionMethod.LZMA)
            out.format("%-52s%s\n", String.format("%s  end-of-stream (EOS) marker:", prefix),
                    generalPurposeFlag.isEosMarker() ? "yes" : "no");
    }

}