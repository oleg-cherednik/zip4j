/*
 * Copyright 2010 Srikanth Reddy Lingala
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.lingala.zip4j.util;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.zip.CRC32;
import java.util.zip.CheckedInputStream;

/**
 * @author Oleg Cherednik
 * @since 07.03.2019
 */
@RequiredArgsConstructor
public final class ChecksumCalculator {

    @NonNull
    private final Path file;

    public long calculate() throws IOException {
        try (CheckedInputStream in = new CheckedInputStream(new FileInputStream(file.toFile()), new CRC32())) {
            byte[] buf = new byte[128];

            while (in.read(buf) >= 0) {
            }

            return in.getChecksum().getValue();
        }
    }
}
