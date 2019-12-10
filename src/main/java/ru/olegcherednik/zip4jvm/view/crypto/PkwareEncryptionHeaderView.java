package ru.olegcherednik.zip4jvm.view.crypto;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import ru.olegcherednik.zip4jvm.model.block.PkwareEncryptionHeaderBlock;
import ru.olegcherednik.zip4jvm.view.ByteArrayHexView;
import ru.olegcherednik.zip4jvm.view.View;

import java.io.PrintStream;
import java.util.Objects;

/**
 * @author Oleg Cherednik
 * @since 09.11.2019
 */
public final class PkwareEncryptionHeaderView extends View {

    private final PkwareEncryptionHeaderBlock encryptionHeader;
    private final long pos;

    public PkwareEncryptionHeaderView(PkwareEncryptionHeaderBlock encryptionHeader, long pos, int offs, int columnWidth) {
        super(offs, columnWidth);
        this.encryptionHeader = encryptionHeader;
        this.pos = pos;

        Objects.requireNonNull(encryptionHeader, "'encryptionHeader' must not be null");
    }

    public static Builder builder() {
        return new Builder();
    }

    private PkwareEncryptionHeaderView(Builder builder) {
        super(builder.offs, builder.columnWidth);
        encryptionHeader = builder.encryptionHeader;
        pos = builder.pos;
    }

    @Override
    public boolean print(PrintStream out) {
        printSubTitle(out, pos, "(PKWARE) encryption header");
        printValueLocation(out, "data:", encryptionHeader.getData());
        return new ByteArrayHexView(encryptionHeader.getData().getData(), offs, columnWidth).print(out);
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class Builder {

        private PkwareEncryptionHeaderBlock encryptionHeader;
        private long pos;
        private int offs;
        private int columnWidth;

        public PkwareEncryptionHeaderView build() {
            return new PkwareEncryptionHeaderView(this);
        }

        public Builder encryptionHeader(PkwareEncryptionHeaderBlock encryptionHeader) {
            this.encryptionHeader = encryptionHeader;
            return this;
        }

        public Builder pos(long pos) {
            this.pos = pos;
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
