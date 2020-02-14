package ru.olegcherednik.zip4jvm.assertj;

import org.apache.commons.lang.StringUtils;
import org.assertj.core.api.AbstractPathAssert;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static ru.olegcherednik.zip4jvm.assertj.Zip4jvmAssertions.assertThatStringLine;

/**
 * @author Oleg Cherednik
 * @since 28.03.2019
 */
@SuppressWarnings("CatchMayIgnoreException")
public class FileAssert extends AbstractPathAssert<FileAssert> implements IFileAssert<FileAssert> {

    public FileAssert(Path actual) {
        super(actual, FileAssert.class);
    }

    @Override
    public FileAssert isImage() {
        try (InputStream in = new FileInputStream(actual.toFile())) {
            assertThat(ImageIO.read(in)).isNotNull();
        } catch(Exception e) {
            assertThatThrownBy(() -> {
                throw e;
            }).doesNotThrowAnyException();
        }

        return myself;
    }

    @Override
    public FileAssert hasSize(long size) {
        try {
            assertThat(Files.size(actual)).isEqualTo(size);
        } catch(Exception e) {
            assertThatThrownBy(() -> {
                throw e;
            }).doesNotThrowAnyException();
        }

        return myself;
    }

    @Override
    public FileAssert matches(Consumer<IFileAssert<?>> consumer) {
        consumer.accept(this);
        return myself;
    }

    @Override
    public FileAssert exists() {
        super.exists();
        isRegularFile();
        return myself;
    }

    private static final Pattern REGEX = Pattern.compile("<--\\sregexp\\((?<regex>.+)\\)\\s-->.+");

    public FileAssert matchesResourceLines(String path) {
        try (BufferedReader actualReader = new BufferedReader(new FileReader(actual.toFile()));
             BufferedReader expectedReader = new BufferedReader(new InputStreamReader(FileAssert.class.getResourceAsStream(path)))) {
            int pos = 0;

            while (true) {
                pos++;
                String actual = actualReader.readLine();
                String expected = expectedReader.readLine();

                if (actual == null && expected == null)
                    break;
                if (StringUtils.equals(actual, expected) || expected.startsWith("<-- ignore_line -->"))
                    continue;

                actual = Optional.ofNullable(actual).orElse("");
                expected = Optional.ofNullable(expected).orElse("");

                Matcher matcher = REGEX.matcher(expected);

                if (matcher.matches()) {
                    String regex = matcher.group("regex");
                    //noinspection ConstantConditions
                    if (Pattern.compile(regex).matcher(actual).matches())
                        continue;

                    throw new AssertionError(
                            String.format("(line %d)\r\nExpecting:\r\n<\"%s\">\r\nto be match the pattern:\r\n<\"%s\">\r\nbut was not.",
                                    pos, actual, regex));
                } else
                    assertThatStringLine(pos, actual).isEqualTo(expected);
            }
        } catch(Exception e) {
            assertThatThrownBy(() -> {
                throw e;
            }).doesNotThrowAnyException();
        }

        return myself;
    }

}
