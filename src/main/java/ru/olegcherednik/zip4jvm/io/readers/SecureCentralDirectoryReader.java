package ru.olegcherednik.zip4jvm.io.readers;

import org.apache.commons.codec.digest.DigestUtils;
import ru.olegcherednik.zip4jvm.crypto.aes.AesStrength;
import ru.olegcherednik.zip4jvm.crypto.strong.DecryptionHeader;
import ru.olegcherednik.zip4jvm.crypto.strong.DecryptionInfo;
import ru.olegcherednik.zip4jvm.crypto.strong.EncryptionAlgorithm;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.model.Charsets;
import ru.olegcherednik.zip4jvm.model.Encryption;
import ru.olegcherednik.zip4jvm.model.Zip64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Function;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
import java.util.zip.Inflater;

/**
 * @author Oleg Cherednik
 * @since 10.10.2019
 */
public final class SecureCentralDirectoryReader extends CentralDirectoryReader {

    private final Zip64.ExtensibleDataSector extensibleDataSector;

    private int nonce;
    private byte[] counter;

    public SecureCentralDirectoryReader(long totalEntries, Function<Charset, Charset> customizeCharset,
            Zip64.ExtensibleDataSector extensibleDataSector) {
        super(totalEntries, customizeCharset);
        this.extensibleDataSector = extensibleDataSector;

        // TODO require not NULL extensibleDataSector
    }

    @Override
    public CentralDirectory read(DataInput in) throws IOException {
        try {
            DecryptionHeader decryptionHeader = new DecryptionHeaderReader().read(in);
            byte[] encrypted = in.readBytes(128);

//            LocalFileHeader localFileHeader = new LocalFileHeaderReader(0, Charsets.UNMODIFIED).read(in);

            generateMasterSessionKey(decryptionHeader);
            generateFileSessionKey();

            AesStrength strength = AesStrength.S128;
//            byte[] salt = Arrays.copyOfRange(decryptionHeader.getEncryptedRandomData(), 0, 16);
            byte[] salt = decryptionHeader.getDecryptionInfo().getEncryptedRandomData();
            byte[] key = createKey("1".toCharArray(), salt, strength);

            nonce = decryptionHeader.getIvSize();
            counter = new byte[decryptionHeader.getIvSize()];

            Cipher cipher = createCipher(strength.createSecretKeyForCipher(key));
            Mac mac = createMac(strength.createSecretKeyForMac(key));
            byte[] passwordChecksum = strength.createPasswordChecksum(key);
//            byte[] expected = in.readBytes(PASSWORD_CHECKSUM_SIZE);

//            byte[] buf = new byte[1024 * 4];

            byte[] buf = in.readBytes(100);
            Inflater inflater = new Inflater(true);
            cypherUpdate(buf, 0, buf.length, cipher, decryptionHeader);

            inflater.inflate(buf);
            cipher.doFinal(buf);
            inflater.setInput(buf);


            int a = 0;
            a++;


//        Decoder decoder = getEncryption().getCreateDecoderCentral().apply(extensibleDataSector, in);


//        try (DataInput inn = new BaseDataInput() {
//            @Override
//            public int read(byte[] buf, int offs, int len) throws IOException {
//                return 0;
//            }
//        }) {
//            CentralDirectory dir = new CentralDirectoryReader(inn.getOffs(), totalEntries, charsetCustomizer).read(inn);
//            return dir;
//        }
//        try (InputStream is = new CentralDirectoryInflateInputStream()) {
//
//        }
        } catch(Exception e) {
            throw new Zip4jvmException(e);
        }

        return null;

    }

    public void cypherUpdate(byte[] buf, int offs, int len, Cipher cipher, DecryptionHeader decryptionHeader) throws ShortBufferException {
        for (int i = 0; i < len; i++) {
            if (nonce == decryptionHeader.getIv().length) {
                ivUpdate(decryptionHeader);
                cipher.update(decryptionHeader.getIv(), 0, decryptionHeader.getIv().length, counter);
                nonce = 0;
            }

            buf[offs + i] ^= counter[nonce++];
        }
    }

    private void ivUpdate(DecryptionHeader decryptionHeader) {
        for (int i = 0; i < decryptionHeader.getIv().length; i++)
            if (++decryptionHeader.getIv()[i] != 0)
                break;
    }

    public static byte[] createKey(char[] password, byte[] salt, AesStrength strength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final int keyLength = strength.getSize() * 2 + 16;
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, 1000, keyLength);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(keySpec).getEncoded();
    }

    public static Cipher createCipher(SecretKeySpec secretKeySpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES");
        // use custom AES implementation, so no worry for DECRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher;
    }

    public static Mac createMac(SecretKeySpec secretKeySpec) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(secretKeySpec);
        return mac;
    }

    private Encryption getEncryption() {
        EncryptionAlgorithm encryptionAlgorithm = extensibleDataSector.getEncryptionAlgorithm();

        if (encryptionAlgorithm == EncryptionAlgorithm.AES_128)
            return Encryption.AES_128;
        if (encryptionAlgorithm == EncryptionAlgorithm.AES_192)
            return Encryption.AES_192;
        if (encryptionAlgorithm == EncryptionAlgorithm.AES_256)
            return Encryption.AES_256;

        throw new Zip4jvmException("Encryption algorithm is not supported: " + encryptionAlgorithm);
    }

    private void generateMasterSessionKey(DecryptionHeader decryptionHeader) throws NoSuchAlgorithmException {
        if (decryptionHeader.getDecryptionInfo().getFlags() == DecryptionInfo.Flags.MASTER_KEY_3DES)
            // TODO use 3DES 3-key MASK algorithm
            return;

        // TODO 1. prompt user for password
        final String password = "666";
        byte[] buf = password.getBytes(Charsets.UTF_8);

        Checksum checksum = new CRC32();
        checksum.update(buf, 0, buf.length);
        long crc32 = checksum.getValue();

        // TODO 2. calculate hash of the password
        // for algorithms that use both Salt and IV, Salt = IV
        // IV can be completely random data and placed in front of Decryption Information; otherwise IV = CRC32 + 64-bit File Size
        String hashPassword = DigestUtils.sha1Hex(password);

        int a = 0;
        a++;
    }

    private void generateFileSessionKey() {

    }
}

class AES {

    private static SecretKeySpec secretKey;
    private static byte[] key;

    public static void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String strToEncrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e)
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
}
