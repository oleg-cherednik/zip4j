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

package net.lingala.zip4j.model;

import com.sun.istack.internal.NotNull;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import net.lingala.zip4j.utils.ZipUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.StringUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.TimeZone;

@Getter
@Setter
@Builder(toBuilder = true)
public class ZipParameters {

    @NonNull
    @Builder.Default
    private CompressionMethod compressionMethod = CompressionMethod.DEFLATE;
    @NonNull
    @Builder.Default
    private CompressionLevel compressionLevel = CompressionLevel.NORMAL;
    @NonNull
    @Builder.Default
    private Encryption encryption = Encryption.OFF;
    private boolean readHiddenFiles;
    private char[] password;
    @Builder.Default
    private AesStrength aesStrength = AesStrength.NONE;
    @Builder.Default
    private boolean includeRootFolder = true;
    private String rootFolderInZip;
    @Builder.Default
    private TimeZone timeZone = TimeZone.getDefault();
    private long sourceFileCRC;
    private Path defaultFolderPath;
    private boolean isSourceExternalStream;
    @Builder.Default
    private long splitLength = ZipModel.NO_SPLIT;
    private String comment;
    public boolean zip64;

    @NotNull
    public CompressionMethod getActualCompressionMethod() {
        return encryption == Encryption.AES ? CompressionMethod.AES_ENC : compressionMethod;
    }

    /**
     * Sets the password for the zip file or the file being added<br>
     * <b>Note</b>: For security reasons, usage of this method is discouraged. Use
     * setPassword(char[]) instead. As strings are immutable, they cannot be wiped
     * out from memory explicitly after usage. Therefore, usage of Strings to store
     * passwords is discouraged. More info here:
     * http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx
     *
     * @param password
     */
    public void setPassword(String password) {
        if (password != null)
            setPassword(password.toCharArray());
    }

    public void setPassword(char[] password) {
        this.password = password;
    }

    public void setRootFolderInZip(String rootFolderInZip) {
        if (StringUtils.isNotBlank(rootFolderInZip)) {

            if (!ZipUtils.isDirectory(rootFolderInZip))
                rootFolderInZip += "/";

            rootFolderInZip = rootFolderInZip.replaceAll("\\\\", "/");

//			if (rootFolderInZip.endsWith("/")) {
//				rootFolderInZip = rootFolderInZip.substring(0, rootFolderInZip.length() - 1);
//				rootFolderInZip = rootFolderInZip + "\\";
//			}
        }
        this.rootFolderInZip = rootFolderInZip;
    }

    @NonNull
    public String getRelativeEntryName(Path entry) {
        Path entryPath = entry.toAbsolutePath();
        Path rootPath = defaultFolderPath != null ? defaultFolderPath : entryPath.getParent();

        String path = rootPath.relativize(entryPath).toString();

        if (Files.isDirectory(entryPath))
            path += File.separator;

        if (rootFolderInZip != null)
            path = FilenameUtils.concat(path, rootFolderInZip);

        return path;
    }

}
