package ru.olegcherednik.zip4jvm.view;

import lombok.Builder;
import ru.olegcherednik.zip4jvm.model.LocalFileHeader;
import ru.olegcherednik.zip4jvm.model.block.Diagnostic;
import ru.olegcherednik.zip4jvm.view.extrafield.ExtraFieldView;

import java.io.PrintStream;
import java.nio.charset.Charset;
import java.util.Optional;
import java.util.stream.IntStream;

/**
 * @author Oleg Cherednik
 * @since 23.10.2019
 */
@Builder
public class LocalFileHeaderView {

    private final LocalFileHeader localFileHeader;
    // TODO should be block
    private final Diagnostic.ZipEntryBlock.LocalFileHeaderB diagLocalFileHeader;
    private final long pos;
    private final Charset charset;
    private final String prefix;

    public void print(PrintStream out) {
        String str = String.format("#%d (%s) Local directory entry - %d bytes",
                pos + 1, ViewUtils.signature(LocalFileHeader.SIGNATURE), diagLocalFileHeader.getContent().getSize());
        out.println(str);

        IntStream.range(0, str.length()).forEach(i -> out.print('='));

        out.println();
        out.format("%sfilename (%s): %s\n\n", prefix, charset.name(), localFileHeader.getFileName());
        out.format("%s--- part number (%04X): %d ---\n", prefix, diagLocalFileHeader.getDisk(), diagLocalFileHeader.getDisk() + 1);
        out.format("%slocation:                                       %2$d (0x%2$08X) bytes\n", prefix, diagLocalFileHeader.getContent().getOffs());

        printVersion(out);
        printGeneralPurposeFlag(out);
        printCompressionMethod(out);
        printLastModifiedTime(out);

        out.format("%s32-bit CRC value:                               0x%2$08X\n", prefix, localFileHeader.getCrc32());
        out.format("%scompressed size:                                %d bytes\n", prefix, localFileHeader.getCompressedSize());
        out.format("%suncompressed size:                              %d bytes\n", prefix, localFileHeader.getUncompressedSize());
        out.format("%slength of filename:                             %d bytes\n", prefix,
                Optional.ofNullable(localFileHeader.getFileName()).orElse("").getBytes(charset).length);
        StringHexView.builder()
                     .str(localFileHeader.getFileName())
                     .charset(charset)
                     .prefix(prefix).build().print(out);

        printExtraField(out);
    }

    private void printVersion(PrintStream out) {
        VersionView.builder()
                   .versionToExtract(localFileHeader.getVersionToExtract())
                   .offs(prefix.length())
                   .columnWidth(52).build().print(out);
    }

    private void printGeneralPurposeFlag(PrintStream out) {
        GeneralPurposeFlagView.builder()
                              .generalPurposeFlag(localFileHeader.getGeneralPurposeFlag())
                              .compressionMethod(localFileHeader.getCompressionMethod())
                              .offs(prefix.length())
                              .columnWidth(52).build().print(out);
    }

    private void printCompressionMethod(PrintStream out) {
        CompressionMethodView.builder()
                             .compressionMethod(localFileHeader.getCompressionMethod())
                             .generalPurposeFlag(localFileHeader.getGeneralPurposeFlag())
                             .offs(prefix.length())
                             .columnWidth(52).build().print(out);
    }

    private void printLastModifiedTime(PrintStream out) {
        LastModifiedTimeView.builder()
                            .lastModifiedTime(localFileHeader.getLastModifiedTime())
                            .prefix(prefix).build().print(out);
    }

    private void printExtraField(PrintStream out) {
        ExtraFieldView.builder()
                      .extraField(localFileHeader.getExtraField())
                      .diagExtraField(diagLocalFileHeader.getExtraField())
                      .generalPurposeFlag(localFileHeader.getGeneralPurposeFlag())
                      .offs(prefix.length())
                      .columnWidth(52).build().print(out);
    }

}