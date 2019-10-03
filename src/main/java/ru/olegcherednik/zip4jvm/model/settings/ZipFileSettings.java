package ru.olegcherednik.zip4jvm.model.settings;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.apache.commons.lang.StringUtils;
import ru.olegcherednik.zip4jvm.model.ZipModel;

import java.util.Optional;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 05.09.2019
 */
@Getter
public final class ZipFileSettings {

    public static final ZipFileSettings DEFAULT = builder().build();

    private final long splitSize;
    private final String comment;
    private final boolean zip64;
    private final Function<String, ZipEntrySettings> entrySettingsProvider;

    public static Builder builder() {
        return new Builder();
    }

    private ZipFileSettings(Builder builder) {
        splitSize = builder.splitSize;
        comment = builder.comment;
        zip64 = builder.zip64;
        entrySettingsProvider = builder.entrySettingsProvider;
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class Builder {

        private long splitSize = ZipModel.NO_SPLIT;
        private String comment;
        private boolean zip64;
        private Function<String, ZipEntrySettings> entrySettingsProvider = ZipEntrySettings.DEFAULT_PROVIDER;

        public ZipFileSettings build() {
            return new ZipFileSettings(this);
        }

        public Builder splitSize(long splitSize) {
            if (splitSize > 0 && splitSize < ZipModel.MIN_SPLIT_SIZE)
                throw new IllegalArgumentException("Zip split size should be <= 0 (no split) or >= " + ZipModel.MIN_SPLIT_SIZE);

            this.splitSize = splitSize;
            return this;
        }

        public Builder comment(String comment) {
            if (StringUtils.length(comment) > ZipModel.MAX_COMMENT_SIZE)
                throw new IllegalArgumentException("File comment should be " + ZipModel.MAX_COMMENT_SIZE + " characters maximum");

            this.comment = StringUtils.isEmpty(comment) ? null : comment;
            return this;
        }

        public Builder zip64(boolean zip64) {
            this.zip64 = zip64;
            return this;
        }

        public Builder entrySettingsProvider(@NonNull Function<String, ZipEntrySettings> entrySettingsProvider) {
            this.entrySettingsProvider = Optional.ofNullable(entrySettingsProvider).orElse(ZipEntrySettings.DEFAULT_PROVIDER);
            return this;
        }
    }

}
