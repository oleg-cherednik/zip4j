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

package net.lingala.zip4j.crypto;

import lombok.NonNull;
import net.lingala.zip4j.crypto.PBKDF2.MacBasedPRF;
import net.lingala.zip4j.crypto.PBKDF2.PBKDF2Engine;
import net.lingala.zip4j.crypto.PBKDF2.PBKDF2Parameters;
import net.lingala.zip4j.crypto.engine.AESEngine;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.exception.ZipExceptionConstants;
import net.lingala.zip4j.model.AESExtraDataRecord;
import net.lingala.zip4j.model.AESStrength;
import net.lingala.zip4j.model.LocalFileHeader;
import net.lingala.zip4j.utils.InternalZipConstants;
import net.lingala.zip4j.utils.Raw;
import org.apache.commons.lang.ArrayUtils;

import java.util.Arrays;

public class AESDecoder implements Decoder {

    @NonNull
    private final LocalFileHeader localFileHeader;
    private final char[] password;
    private AESEngine aesEngine;
    private MacBasedPRF mac;

    private final int PASSWORD_VERIFIER_LENGTH = 2;
    private int KEY_LENGTH;
    private int MAC_LENGTH;
    private int SALT_LENGTH;

    private byte[] aesKey;
    private byte[] macKey;
    private byte[] derivedPasswordVerifier;
    private byte[] storedMac;

    private int nonce = 1;
    private byte[] iv;
    private byte[] counterBlock;
    private int loopCount = 0;

    public AESDecoder(@NonNull LocalFileHeader localFileHeader, char[] password, byte[] salt, byte[] passwordVerifier) throws ZipException {
        this.localFileHeader = localFileHeader;
        this.password = password;
        storedMac = null;
        iv = new byte[InternalZipConstants.AES_BLOCK_SIZE];
        counterBlock = new byte[InternalZipConstants.AES_BLOCK_SIZE];
        init(salt, passwordVerifier);
    }

    private void init(byte[] salt, byte[] passwordVerifier) throws ZipException {
        AESExtraDataRecord aesExtraDataRecord = localFileHeader.getExtraField().getAesExtraDataRecord();

        if (aesExtraDataRecord == AESExtraDataRecord.NULL)
            throw new ZipException("invalid aes extra data record - in init method of AESDecryptor");

        SALT_LENGTH = aesExtraDataRecord.getAesStrength().getSaltLength();

        if (aesExtraDataRecord.getAesStrength() == AESStrength.NONE)
            throw new ZipException("invalid aes key strength for file: " + localFileHeader.getFileName());

        if (aesExtraDataRecord.getAesStrength() == AESStrength.STRENGTH_128) {
            KEY_LENGTH = 16;
            MAC_LENGTH = 16;
        } else if (aesExtraDataRecord.getAesStrength() == AESStrength.STRENGTH_192) {
            KEY_LENGTH = 24;
            MAC_LENGTH = 24;
        } else if (aesExtraDataRecord.getAesStrength() == AESStrength.STRENGTH_256) {
            KEY_LENGTH = 32;
            MAC_LENGTH = 32;
        }

        if (ArrayUtils.isEmpty(password))
            throw new ZipException("empty or null password provided for AES Decryptor");

        byte[] derivedKey = deriveKey(salt, password);
        if (derivedKey == null ||
                derivedKey.length != (KEY_LENGTH + MAC_LENGTH + PASSWORD_VERIFIER_LENGTH)) {
            throw new ZipException("invalid derived key");
        }

        aesKey = new byte[KEY_LENGTH];
        macKey = new byte[MAC_LENGTH];
        derivedPasswordVerifier = new byte[PASSWORD_VERIFIER_LENGTH];

        System.arraycopy(derivedKey, 0, aesKey, 0, KEY_LENGTH);
        System.arraycopy(derivedKey, KEY_LENGTH, macKey, 0, MAC_LENGTH);
        System.arraycopy(derivedKey, KEY_LENGTH + MAC_LENGTH, derivedPasswordVerifier, 0, PASSWORD_VERIFIER_LENGTH);

        if (derivedPasswordVerifier == null) {
            throw new ZipException("invalid derived password verifier for AES");
        }

        if (!Arrays.equals(passwordVerifier, derivedPasswordVerifier)) {
            throw new ZipException("Wrong Password for file: " + localFileHeader.getFileName(), ZipExceptionConstants.WRONG_PASSWORD);
        }

        aesEngine = new AESEngine(aesKey);
        mac = new MacBasedPRF("HmacSHA1");
        mac.init(macKey);
    }

    public int decode(byte[] buf, int start, int len) throws ZipException {

        if (aesEngine == null) {
            throw new ZipException("AES not initialized properly");
        }

        try {

            for (int j = start; j < (start + len); j += InternalZipConstants.AES_BLOCK_SIZE) {
                loopCount = (j + InternalZipConstants.AES_BLOCK_SIZE <= (start + len)) ?
                            InternalZipConstants.AES_BLOCK_SIZE : ((start + len) - j);

                mac.update(buf, j, loopCount);
                Raw.prepareBuffAESIVBytes(iv, nonce, InternalZipConstants.AES_BLOCK_SIZE);
                aesEngine.processBlock(iv, counterBlock);

                for (int k = 0; k < loopCount; k++) {
                    buf[j + k] = (byte)(buf[j + k] ^ counterBlock[k]);
                }

                nonce++;
            }

            return len;

        } catch(ZipException e) {
            throw e;
        } catch(Exception e) {
            throw new ZipException(e);
        }
    }

    public int decode(byte[] buf) throws ZipException {
        return decode(buf, 0, buf.length);
    }

    private byte[] deriveKey(byte[] salt, char[] password) throws ZipException {
        try {
            PBKDF2Parameters p = new PBKDF2Parameters("HmacSHA1", "ISO-8859-1",
                    salt, 1000);
            PBKDF2Engine e = new PBKDF2Engine(p);
            byte[] derivedKey = e.deriveKey(password, KEY_LENGTH + MAC_LENGTH + PASSWORD_VERIFIER_LENGTH);
            return derivedKey;
        } catch(Exception e) {
            throw new ZipException(e);
        }
    }

    public int getPasswordVerifierLength() {
        return PASSWORD_VERIFIER_LENGTH;
    }

    public int getSaltLength() {
        return SALT_LENGTH;
    }

    public byte[] getCalculatedAuthenticationBytes() {
        return mac.doFinal();
    }

    public void setStoredMac(byte[] storedMac) {
        this.storedMac = storedMac;
    }

    public byte[] getStoredMac() {
        return storedMac;
    }

//	public byte[] getStoredMac() throws ZipException {
//		if (raf == null) {
//			throw new ZipException("attempting to read MAC on closed file handle");
//		}
//
//		try {
//			byte[] storedMacBytes = new byte[InternalZipConstants.AES_AUTH_LENGTH];
//			int bytesRead = raf.read(storedMacBytes);
//			if (bytesRead != InternalZipConstants.AES_AUTH_LENGTH) {
//				if (zipModel.isSplitArchive()) {
////					unzipEngine.startNextSplitFile();
//					if (bytesRead == -1) bytesRead = 0;
//					int newlyRead = raf.read(storedMacBytes, bytesRead, InternalZipConstants.AES_AUTH_LENGTH - bytesRead);
//					bytesRead += newlyRead;
//					if (bytesRead != InternalZipConstants.AES_AUTH_LENGTH) {
//						throw new ZipException("invalid number of bytes read for stored MAC after starting split file");
//					}
//				} else {
//					throw new ZipException("invalid number of bytes read for stored MAC");
//				}
//			}
//			return storedMacBytes;
//		} catch (IOException e) {
//			throw new ZipException(e);
//		} catch (Exception e) {
//			throw new ZipException(e);
//		}
//
//	}
}