package com.cop.zip4j.foo;

import com.cop.zip4j.crypto.aes.AesEngine;
import com.cop.zip4j.crypto.aes.pbkdf2.PBKDF2Engine;
import com.cop.zip4j.crypto.aes.pbkdf2.PBKDF2Parameters;
import com.cop.zip4j.model.aes.AesStrength;
import de.idyl.winzipaes.AesZipFileDecrypter;
import de.idyl.winzipaes.impl.AESDecrypter;
import de.idyl.winzipaes.impl.AESDecrypterBC;
import de.idyl.winzipaes.impl.ExtZipEntry;
import org.apache.commons.lang.ArrayUtils;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import static com.cop.zip4j.crypto.aes.AesCipherUtil.prepareBuffAESIVBytes;
import static com.cop.zip4j.crypto.aes.AesEngine.AES_BLOCK_SIZE;
import static com.cop.zip4j.foo.AesDecoder.PASSWORD_VERIFIER_LENGTH;

/**
 * @author Oleg Cherednik
 * @since 30.07.2019
 */
public class AES {

    private static final byte[] salt = {
            (byte)-5, (byte)76, (byte)-57, (byte)-47, (byte)-20,
            (byte)-120, (byte)54, (byte)69, (byte)102, (byte)-87,
            (byte)92, (byte)-5, (byte)48, (byte)57, (byte)-49, (byte)-88 };
    private static final byte[] passwordVerifier = { (byte)0xC2, (byte)0x65 };

    //    private static final String aes = "AES/CTR/PKCS5Padding";
    private static final String aes = "AES/CTR/NoPadding";
    private static final String pbk = "PBKDF2WithHmacSHA1";

    public static byte[] encrypt(String str, String secret) {
        try {
            IvParameterSpec ivspec = new IvParameterSpec(new byte[16]);

            SecretKeyFactory factory = SecretKeyFactory.getInstance(pbk);
            KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt, 1000, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance(aes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(str.getBytes(StandardCharsets.UTF_8));
        } catch(Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(byte[] buf, String secret) {
        try {
            IvParameterSpec ivspec = new IvParameterSpec(new byte[16]);

            SecretKeyFactory factory = SecretKeyFactory.getInstance(pbk);
            KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt, 1000, 256);
            SecretKey tmp = factory.generateSecret(spec);
            byte[] keyb = tmp.getEncoded();
            SecretKeySpec skey = new SecretKeySpec(keyb, "AES");

            Cipher cipher = Cipher.getInstance(aes);
            cipher.init(Cipher.DECRYPT_MODE, skey, ivspec);
            return new String(cipher.doFinal(buf), StandardCharsets.UTF_8);
        } catch(Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static String decryptOld(byte[] buf, String password) throws Exception {
        AesStrength strength = AesStrength.KEY_STRENGTH_256;
        int length = strength.getKeyLength() + strength.getMacLength() + PASSWORD_VERIFIER_LENGTH;
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000, length * 8);
        SecretKey secretKey = factory.generateSecret(spec);
        byte[] aesKey = secretKey.getEncoded();
        System.out.println(Arrays.toString(aesKey));
        System.out.println("-------------");

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                new IvParameterSpec(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));

        byte[] res = cipher.doFinal(buf);


        AesDecoder decoder = new AesDecoder(AesStrength.KEY_STRENGTH_256, password.toCharArray(), salt, passwordVerifier);
        int len = decoder.decrypt(buf, 0, buf.length);
        return new String(buf, StandardCharsets.UTF_8);
    }

    public static String decryptNew(String password) throws Exception {
        AESDecrypter decrypter = new AESDecrypterBC();
        AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(new File("d:/zip4j/aes.zip"), decrypter);
        ExtZipEntry entry = aesDecryptor.getEntry("foo.txt");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        aesDecryptor.extractEntry(entry, out, password);
        return out.toString();
    }
}

@SuppressWarnings("MethodCanBeVariableArityMethod")
class AesDecoder {

    public static final int PASSWORD_VERIFIER_LENGTH = 2;

    private final AesStrength strength;
    private final char[] password;
    private AesEngine aesEngine;
    private Mac mac;

    private int nonce = 1;
    private final byte[] iv = new byte[AES_BLOCK_SIZE];
    private final byte[] counterBlock = new byte[AES_BLOCK_SIZE];

    public AesDecoder(AesStrength strength, char[] password, byte[] salt, byte[] passwordVerifier)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        this.strength = strength;
        this.password = ArrayUtils.clone(password);


        init(salt, passwordVerifier);
    }

    private void init(byte[] salt, byte[] passwordVerifier) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password, salt, 1000, 256);
        SecretKey secretKey = factory.generateSecret(spec);
        byte[] aesKey = secretKey.getEncoded();

//        byte[] derivedKey = deriveKey(salt);
//        byte[] macKey = new byte[strength.getMacLength()];
//        byte[] derivedPasswordVerifier = new byte[PASSWORD_VERIFIER_LENGTH];

//        System.arraycopy(derivedKey, strength.getKeyLength(), macKey, 0, strength.getMacLength());
//        System.arraycopy(derivedKey, strength.getKeyLength() + strength.getMacLength(), derivedPasswordVerifier, 0, PASSWORD_VERIFIER_LENGTH);

//        System.out.println(Arrays.toString(derivedKey));
        System.out.println(Arrays.toString(aesKey));
//        System.out.println(Arrays.toString(macKey));
//        System.out.println(Arrays.toString(derivedPasswordVerifier));

//        if (!Arrays.equals(passwordVerifier, derivedPasswordVerifier))
//            throw new Zip4jException("Wrong Password");

        aesEngine = new AesEngine(aesKey);

        mac = Mac.getInstance("HmacSHA1");
        mac.init(secretKey);
        int a = 0;
        a++;
    }

    public int decrypt(byte[] buf, int offs, int len) {
        for (int j = offs; j < (offs + len); j += AES_BLOCK_SIZE) {
            int loopCount = (j + AES_BLOCK_SIZE <= (offs + len)) ? AES_BLOCK_SIZE : ((offs + len) - j);

            mac.update(buf, j, loopCount);
            prepareBuffAESIVBytes(iv, nonce);
            aesEngine.processBlock(iv, counterBlock);

            for (int k = 0; k < loopCount; k++)
                buf[j + k] ^= counterBlock[k];

            nonce++;
        }

        return len;
    }

    private byte[] deriveKey(byte[] salt) {
        PBKDF2Engine e = new PBKDF2Engine(new PBKDF2Parameters("HmacSHA1", "ISO-8859-1", salt, 1000));
        return e.deriveKey(password, strength.getKeyLength() + strength.getMacLength() + PASSWORD_VERIFIER_LENGTH);
    }

}