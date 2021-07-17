import org.testng.Assert;
import org.testng.annotations.Test;

public class EncrypterTest {
  String password = "password123";
  String clearText = "durian";

  /**
   * Ensure that encrypt produces different values for the same value.
   */
  @Test
  public void salt() throws Exception {
    Encrypter encrypter = new Encrypter(password);
    String cipherText = encrypter.encrypt(clearText);
    String cipherText2 = encrypter.encrypt(clearText);
    Assert.assertNotEquals(clearText, cipherText);
    Assert.assertNotEquals(clearText, cipherText2);
    Assert.assertNotEquals(cipherText, cipherText2);

    // Ensure both decrypt to the same value
    Assert.assertEquals(encrypter.decrypt(cipherText), clearText);
    Assert.assertEquals(encrypter.decrypt(cipherText2), clearText);
  }

  @Test
  public void decryptOpensslEncryptedText() throws Exception {
    // This ciper text was generated with the following openssl command:
    // $> echo -n "durian" | openssl enc -aes-256-cbc -pass pass:password123 -md sha256 -a
    String cipherText = "U2FsdGVkX1+3N0QSj/8w/2SxUsqo3CoWfqziD8GJdcc=";

    Encrypter encrypter = new Encrypter(password);
    Assert.assertEquals(encrypter.decrypt(cipherText), clearText);
  }

  @Test
  public void decryptWithOpenssl() throws Exception {
    String cipherText = new Encrypter(password).encrypt(clearText);
    System.out.printf("Execute the following command in the shell and ensure that the output equals \"%s\"\n", clearText);
    System.out.printf("  echo \"%s\" | openssl enc -d -aes-256-cbc -md sha256 -pass pass:%s -a\n", cipherText, password);
  }
}
