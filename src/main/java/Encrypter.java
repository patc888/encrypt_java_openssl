import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

/**
 * This encrypter encrypts and decrypts values that are compatible with openssl. In particular, it uses SHA-256 to
 * generate a key with salt and AES-256-CBC symmetric encryption algorithm. In openssl, use the parameters: -aes-256-cbc
 * and -md sha256. e.g.
 * <code>
 * echo -n "text" | openssl enc -aes-256-cbc -md sha256 -pass pass:password123 -a
 * </code>
 */
public class Encrypter {
  SecureRandom srand = new SecureRandom();
  byte[] password;

  /**
   * The supplied password will be used to encrypt/decrypt text. The algorithm uses SHA-256 to generate a key and
   * AES-256-CBC to encrypt the data.
   *
   * @param password A non-null password string of any size. Ideally it should be at least 32 characters.
   */
  public Encrypter(String password) {
    this.password = password.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Encrypts the supplied text.
   *
   * @param clearText
   * @return
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws InvalidAlgorithmParameterException
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public String encrypt(String clearText) throws NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    // Generate salt
    byte[] salt = new byte[8];
    srand.nextBytes(salt);

    // Derive key
    byte[] passAndSalt = concat(password, salt);
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] key = md.digest(passAndSalt);
    SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

    // Derive iv
    md.reset();
    byte[] iv = Arrays.copyOfRange(md.digest(concat(key, passAndSalt)), 0, 16);

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.writeBytes("Salted__".getBytes(StandardCharsets.US_ASCII));
    bos.writeBytes(salt);
    bos.writeBytes(cipher.doFinal(clearText.getBytes(StandardCharsets.UTF_8)));
    return Base64.getEncoder().encodeToString(bos.toByteArray());
  }

  public String decrypt(String cipherText) throws NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    // Parse cipher text
    byte[] cipherBytes = Base64.getDecoder().decode(cipherText);
    byte[] salt = Arrays.copyOfRange(cipherBytes, 8, 16);
    cipherBytes = Arrays.copyOfRange(cipherBytes, 16, cipherBytes.length);

    // Derive key
    byte[] passAndSalt = concat(password, salt);
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] key = md.digest(passAndSalt);
    SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

    // Derive IV
    md.reset();
    byte[] iv = Arrays.copyOfRange(md.digest(concat(key, passAndSalt)), 0, 16);

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
    return new String(cipher.doFinal(cipherBytes));
  }

  /**
   * Returns a new byte array concatenating the contents of a and b.
   *
   * @param a A non-null byte array.
   * @param b A non-null byte array.
   * @return A non-null byte array with the contents of a and b.
   */
  private byte[] concat(byte[] a, byte[] b) {
    byte[] c = new byte[a.length + b.length];
    System.arraycopy(a, 0, c, 0, a.length);
    System.arraycopy(b, 0, c, a.length, b.length);
    return c;
  }
}
