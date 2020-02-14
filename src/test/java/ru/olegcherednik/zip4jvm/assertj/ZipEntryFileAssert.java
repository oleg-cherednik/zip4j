package ru.olegcherednik.zip4jvm.assertj;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import ru.olegcherednik.zip4jvm.model.Charsets;

import javax.imageio.ImageIO;
import java.io.InputStream;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

/**
 * @author Oleg Cherednik
 * @since 25.03.2019
 */
@SuppressWarnings("CatchMayIgnoreException")
public class ZipEntryFileAssert extends AbstractZipEntryAssert<ZipEntryFileAssert> implements IFileAssert<ZipEntryFileAssert> {

    private static final Pattern NEW_LINE = Pattern.compile("\\r?\\n");

    public ZipEntryFileAssert(ZipEntry actual, ZipFileDecorator zipFile) {
        super(actual, ZipEntryFileAssert.class, zipFile);
    }

    @Override
    public ZipEntryFileAssert hasSize(long size) {
        if (actual.getSize() == -1) {
            try (InputStream in = zipFile.getInputStream(actual)) {
                byte[] buf = new byte[1024 * 4];
                int available = 0;
                int res;

                while ((res = in.read(buf)) != IOUtils.EOF)
                    available += res;

                actual.setSize(available);
            } catch(Exception e) {
                assertThatThrownBy(() -> {
                    throw e;
                }).doesNotThrowAnyException();
            }
        }

        assertThat(actual.getSize()).isEqualTo(size);
        return myself;
    }

    @Override
    public ZipEntryFileAssert isImage() {
        try (InputStream in = zipFile.getInputStream(actual)) {
            assertThat(ImageIO.read(in)).isNotNull();
        } catch(Exception e) {
            assertThatThrownBy(() -> {
                throw e;
            }).doesNotThrowAnyException();
        }

        return myself;
    }

    public ZipEntryFileAssert hasEmptyContent() {
        return hasContent("");
    }

    public ZipEntryFileAssert hasContent(String expected) {
        try (InputStream in = zipFile.getInputStream(actual)) {
            String[] expectedLines = expected.isEmpty() ? ArrayUtils.EMPTY_STRING_ARRAY : NEW_LINE.split(expected);

            List<String> lines = IOUtils.readLines(in, Charsets.UTF_8);
            assertThat(lines).hasSize(expectedLines.length);

            int i = 0;

            for (String line : lines)
                assertThat(line).isEqualTo(expectedLines[i++]);
        } catch(Exception e) {
            assertThatThrownBy(() -> {
                throw e;
            }).doesNotThrowAnyException();
        }

        return myself;
    }

    public ZipEntryFileAssert hasComment(String comment) {
        if (comment == null)
            assertThat(actual.getComment()).isNull();
        else
            assertThat(actual.getComment()).isEqualTo(comment);
        return myself;
    }

    @Override
    public ZipEntryFileAssert matches(Consumer<IFileAssert<?>> consumer) {
        consumer.accept(this);
        return myself;
    }
}
