package net.lingala.zip4j.assertj;

import lombok.Getter;
import lombok.NonNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

/**
 * @author Oleg Cherednik
 * @since 27.03.2019
 */
final class ZipFileDecorator {

    @Getter
    private final Path path;
    private final Map<String, ZipEntry> entries;
    private final Map<String, Set<String>> map;

    public ZipFileDecorator(Path path) {
        this.path = path;
        entries = entries(path);
        map = walk(entries.keySet());
    }

    public boolean containsEntry(String entryName) {
        return entries.containsKey(entryName) || map.containsKey(entryName);
    }

    public Set<String> getSubEntries(String entryName) {
        return map.containsKey(entryName) ? Collections.unmodifiableSet(map.get(entryName)) : Collections.emptySet();
    }

    public InputStream getInputStream(@NonNull ZipEntry entry) {
        try {
            return new ZipFile(path.toFile()).getInputStream(entry);
        } catch(Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Map<String, ZipEntry> entries(Path path) {
        try (ZipFile zipFile = new ZipFile(path.toFile())) {
            Map<String, ZipEntry> map = zipFile.stream().collect(Collectors.toMap(ZipEntry::getName, Function.identity()));
            map.values().forEach(entry -> {
                try {
                    zipFile.getInputStream(entry).available();
                } catch(IOException e) {
                    throw new RuntimeException(e);
                }
            });
            return map;
        } catch(ZipException e) {
            return Collections.emptyMap();
        } catch(Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Map<String, Set<String>> walk(Set<String> entries) {
        Map<String, Set<String>> map = new HashMap<>();
        entries.forEach(entryName -> add(entryName, map));
        return map;
    }

    private static void add(String entryName, Map<String, Set<String>> map) {
        if ("/".equals(entryName))
            return;
        if (entryName.charAt(0) == '/')
            entryName = entryName.substring(1);

        int offs = 0;
        String parent = "/";

        while (parent != null) {
            map.computeIfAbsent(parent, val -> new HashSet<>());
            int pos = entryName.indexOf('/', offs);

            if (pos >= 0) {
                String part = entryName.substring(offs, pos + 1);
                String path = entryName.substring(0, pos + 1);

                map.computeIfAbsent(path, val -> new HashSet<>());
                map.get(parent).add(part);

                offs = pos + 1;
                parent = path;
            } else {
                if (offs < entryName.length())
                    map.get(parent).add(entryName.substring(offs));
                parent = null;
            }
        }
    }

}