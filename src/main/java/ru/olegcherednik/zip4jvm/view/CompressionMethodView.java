package ru.olegcherednik.zip4jvm.view;

import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.model.GeneralPurposeFlag;

import java.io.PrintStream;

import static ru.olegcherednik.zip4jvm.utils.ValidationUtils.requireNotNull;

/**
 * @author Oleg Cherednik
 * @since 15.10.2019
 */
public final class CompressionMethodView extends BaseView {

    private final CompressionMethod compressionMethod;
    private final GeneralPurposeFlag generalPurposeFlag;

    public CompressionMethodView(CompressionMethod compressionMethod, GeneralPurposeFlag generalPurposeFlag, int offs, int columnWidth) {
        super(offs, columnWidth);
        this.compressionMethod = requireNotNull(compressionMethod, "CompressionMethodView.compressionMethod");
        this.generalPurposeFlag = requireNotNull(generalPurposeFlag, "CompressionMethodView.generalPurposeFlag");
    }

    @Override
    public boolean print(PrintStream out) {
        printLine(out, String.format("compression method (%02d):", compressionMethod.getCode()), compressionMethod.getTitle());

        if (compressionMethod == CompressionMethod.FILE_IMPLODED) {
            printLine(out, "  size of sliding dictionary (implosion):", generalPurposeFlag.getSlidingDictionarySize().getTitle());
            printLine(out, "  number of Shannon-Fano trees (implosion):", generalPurposeFlag.getShannonFanoTreesNumber().getTitle());
        } else if (compressionMethod == CompressionMethod.LZMA)
            printLine(out, "  end-of-stream (EOS) marker:", generalPurposeFlag.isLzmaEosMarker() ? "yes" : "no");
        else if (compressionMethod == CompressionMethod.DEFLATE || compressionMethod == CompressionMethod.ENHANCED_DEFLATE)
            printLine(out, "  compression sub-type (deflation):", generalPurposeFlag.getCompressionLevel().getTitle());

        return true;
    }

}
