package ru.olegcherednik.zip4jvm.view.entry;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.lang.ArrayUtils;
import ru.olegcherednik.zip4jvm.model.Charsets;
import ru.olegcherednik.zip4jvm.model.LocalFileHeader;
import ru.olegcherednik.zip4jvm.model.block.Block;
import ru.olegcherednik.zip4jvm.model.block.BlockZipEntryModel;
import ru.olegcherednik.zip4jvm.view.View;

import java.io.PrintStream;
import java.nio.charset.Charset;
import java.util.Optional;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 20.10.2019
 */
public final class ZipEntryListView extends View {

    private final BlockZipEntryModel blockZipEntryModel;
    private final Function<Block, byte[]> getDataFunc;
    private final Charset charset;

    public static Builder builder() {
        return new Builder();
    }

    private ZipEntryListView(Builder builder) {
        super(builder.offs, builder.columnWidth);
        blockZipEntryModel = builder.blockZipEntryModel;
        getDataFunc = builder.getDataFunc;
        charset = builder.charset;
    }

    @Override
    public boolean print(PrintStream out) {
        printTitle(out, LocalFileHeader.SIGNATURE, "ZIP entries");
        printLine(out, "total entries:", String.valueOf(blockZipEntryModel.getLocalFileHeaders().size()));
        printZipEntries(out);
        return true;
    }

    private void printZipEntries(PrintStream out) {
        int pos = 0;

        for (LocalFileHeader localFileHeader : blockZipEntryModel.getLocalFileHeaders().values()) {
            out.println();

            ZipEntryView.builder()
                        .pos(pos)
                        .localFileHeader(localFileHeader)
                        .diagLocalFileHeader(blockZipEntryModel.getZipEntryBlock().getLocalFileHeader(localFileHeader.getFileName()))
                        .encryptionHeader(blockZipEntryModel.getZipEntryBlock().getEncryptionHeader(localFileHeader.getFileName()))
                        .dataDescriptor(blockZipEntryModel.getDataDescriptors().get(localFileHeader.getFileName()))
                        .blockDataDescriptor(blockZipEntryModel.getZipEntryBlock().getDataDescriptor(localFileHeader.getFileName()))
                        .getDataFunc(getDataFunc)
                        .charset(charset)
                        .offs(offs)
                        .columnWidth(columnWidth).build().print(out);

            pos++;
        }
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class Builder {

        private BlockZipEntryModel blockZipEntryModel;
        private Function<Block, byte[]> getDataFunc = block -> ArrayUtils.EMPTY_BYTE_ARRAY;
        private Charset charset = Charsets.IBM437;
        private int offs;
        private int columnWidth;

        public ZipEntryListView build() {
            // blockZipEntryModel == null
            // MapUtils.isEmpty(blockZipEntryModel.getLocalFileHeaders()
            return new ZipEntryListView(this);
        }

        public Builder blockZipEntryModel(BlockZipEntryModel blockZipEntryModel) {
            this.blockZipEntryModel = blockZipEntryModel;
            return this;
        }

        public Builder getDataFunc(Function<Block, byte[]> getDataFunc) {
            this.getDataFunc = Optional.ofNullable(getDataFunc).orElseGet(() -> block -> ArrayUtils.EMPTY_BYTE_ARRAY);
            return this;
        }

        public Builder charset(Charset charset) {
            this.charset = Optional.ofNullable(charset).orElse(Charsets.IBM437);
            return this;
        }

        public Builder position(int offs, int columnWidth) {
            this.offs = offs;
            this.columnWidth = columnWidth;
            return this;
        }

    }
}
