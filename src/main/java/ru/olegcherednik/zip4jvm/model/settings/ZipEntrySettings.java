package ru.olegcherednik.zip4jvm.model.settings;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import ru.olegcherednik.zip4jvm.exception.EmptyPasswordException;
import ru.olegcherednik.zip4jvm.model.Compression;
import ru.olegcherednik.zip4jvm.model.CompressionLevel;
import ru.olegcherednik.zip4jvm.model.Encryption;
import ru.olegcherednik.zip4jvm.model.ZipModel;

import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 05.09.2019
 */
@Getter
public final class ZipEntrySettings {

    public static final ZipEntrySettings DEFAULT = builder().build();
    public static final Function<String, ZipEntrySettings> DEFAULT_PROVIDER = fileName -> DEFAULT;

    private final Compression compression;
    private final CompressionLevel compressionLevel;
    private final Encryption encryption;
    private final char[] password;
    private final String comment;
    private final boolean zip64;
    private final boolean utf8;
    private final boolean lzmaEosMarker;

    public static Builder builder() {
        return new Builder();
    }

    public Builder toBuilder() {
        return new Builder(this);
    }

    private ZipEntrySettings(Builder builder) {
        compression = builder.compression;
        compressionLevel = builder.compressionLevel;
        encryption = builder.encryption;
        password = builder.password;
        comment = builder.comment;
        zip64 = builder.zip64;
        utf8 = builder.utf8;
        lzmaEosMarker = builder.lzmaEosMarker;
    }

    @SuppressWarnings("MethodCanBeVariableArityMethod")
    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class Builder {

        private Compression compression = Compression.DEFLATE;
        private CompressionLevel compressionLevel = CompressionLevel.NORMAL;
        private Encryption encryption = Encryption.OFF;
        private char[] password;
        private String comment;
        private boolean zip64;
        private boolean utf8 = true;
        private boolean lzmaEosMarker = true;

        private Builder(ZipEntrySettings entrySettings) {
            compression = entrySettings.compression;
            compressionLevel = entrySettings.compressionLevel;
            encryption = entrySettings.encryption;
            password = ArrayUtils.clone(entrySettings.password);
            comment = entrySettings.comment;
            zip64 = entrySettings.zip64;
            utf8 = entrySettings.utf8;
            lzmaEosMarker = entrySettings.lzmaEosMarker;
        }

        public ZipEntrySettings build() {
            if (encryption != Encryption.OFF && ArrayUtils.isEmpty(password))
                throw new EmptyPasswordException();

            return new ZipEntrySettings(this);
        }

        public ZipEntrySettings.Builder compression(Compression compression, CompressionLevel compressionLevel) {
            this.compression = compression;
            this.compressionLevel = compressionLevel;
            return this;
        }

        public ZipEntrySettings.Builder encryption(Encryption encryption, char[] password) {
            if (encryption != Encryption.OFF) {
                this.encryption = encryption;
                this.password = ArrayUtils.clone(password);
            }

            return this;
        }

        public ZipEntrySettings.Builder password(char[] password) {
            this.password = ArrayUtils.clone(password);
            return this;
        }

        public ZipEntrySettings.Builder comment(String comment) {
            if (StringUtils.length(comment) > ZipModel.MAX_COMMENT_SIZE)
                throw new IllegalArgumentException("Entry comment should not exceed '" + ZipModel.MAX_COMMENT_SIZE + "' in length");

            this.comment = comment;
            return this;
        }

        public ZipEntrySettings.Builder zip64(boolean zip64) {
            this.zip64 = zip64;
            return this;
        }

        public ZipEntrySettings.Builder utf8(boolean utf8) {
            this.utf8 = utf8;
            return this;
        }

        public ZipEntrySettings.Builder lzmaEosMarker(boolean lzmaEosMarker) {
            this.lzmaEosMarker = lzmaEosMarker;
            return this;
        }

    }
}
