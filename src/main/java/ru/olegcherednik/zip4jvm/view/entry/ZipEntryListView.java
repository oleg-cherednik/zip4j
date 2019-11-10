package ru.olegcherednik.zip4jvm.view.entry;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import ru.olegcherednik.zip4jvm.model.Charsets;
import ru.olegcherednik.zip4jvm.model.LocalFileHeader;
import ru.olegcherednik.zip4jvm.model.block.BlockZipEntryModel;
import ru.olegcherednik.zip4jvm.view.View;

import java.io.PrintStream;
import java.nio.charset.Charset;
import java.util.Optional;

/**
 * @author Oleg Cherednik
 * @since 20.10.2019
 */
public final class ZipEntryListView extends View {

    private final BlockZipEntryModel blockZipEntryModel;
    private final Charset charset;

    public static Builder builder() {
        return new Builder();
    }

    private ZipEntryListView(Builder builder) {
        super(builder.offs, builder.columnWidth);
        blockZipEntryModel = builder.blockZipEntryModel;
        charset = builder.charset;
    }

    @Override
    public void print(PrintStream out) {
        if (blockZipEntryModel == null || blockZipEntryModel.getLocalFileHeaders() == null || blockZipEntryModel.getLocalFileHeaders().isEmpty())
            return;

        printTitle(out, "Zip entry:");
        out.println();
        printLine(out, "total number of entries:", String.valueOf(blockZipEntryModel.getLocalFileHeaders().size()));
        out.println();
        printZipEntries(out);
    }

    private void printZipEntries(PrintStream out) {
        int pos = 0;

        for (LocalFileHeader localFileHeader : blockZipEntryModel.getLocalFileHeaders().values()) {
            if (pos != 0)
                out.println();

            ZipEntryView.builder()
                        .pos(pos)
                        .localFileHeader(localFileHeader)
                        .diagLocalFileHeader(blockZipEntryModel.getZipEntryBlock().getLocalFileHeader(localFileHeader.getFileName()))
                        .encryptionHeader(blockZipEntryModel.getZipEntryBlock().getEncryptionHeader(localFileHeader.getFileName()))
                        .dataDescriptor(blockZipEntryModel.getDataDescriptors().get(localFileHeader.getFileName()))
                        .blockDataDescriptor(blockZipEntryModel.getZipEntryBlock().getDataDescriptor(localFileHeader.getFileName()))
                        .charset(charset)
                        .offs(prefix.length())
                        .columnWidth(52).build().print(out);

            pos++;
        }
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class Builder {

        private BlockZipEntryModel blockZipEntryModel;
        private Charset charset = Charsets.IBM437;
        private int offs;
        private int columnWidth;

        public ZipEntryListView build() {
            return new ZipEntryListView(this);
        }

        public Builder blockZipEntryModel(BlockZipEntryModel blockZipEntryModel) {
            this.blockZipEntryModel = blockZipEntryModel;
            return this;
        }

        public Builder charset(Charset charset) {
            this.charset = Optional.ofNullable(charset).orElse(Charsets.IBM437);
            return this;
        }

        public Builder offs(int offs) {
            this.offs = offs;
            return this;
        }

        public Builder columnWidth(int columnWidth) {
            this.columnWidth = columnWidth;
            return this;
        }
    }
}
