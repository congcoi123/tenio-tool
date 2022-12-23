/*
The MIT License

Copyright (c) 2016-2022 kong <congcoi123@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package com.tenio.tool.crypto;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AesKeysHelper {

  private Cipher encryptCipher;
  private Cipher decryptCipher;

  public void generateSymmetricKey(String keyName)
      throws NoSuchAlgorithmException, IOException {
    KeyGenerator generator = KeyGenerator.getInstance("AES");
    generator.init(128);
    SecretKey key = generator.generateKey();

    try (FileOutputStream fos = new FileOutputStream(keyName)) {
      fos.write(key.getEncoded());
    }

    System.out.println("Generated a symmetric key: " + keyName);
    System.out.println("Key: " + keyToString(key));
  }

  public SecretKey getKey(String keyPath) throws IOException {
    File keyFile = new File(keyPath);
    byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
    return new SecretKeySpec(keyBytes, "AES");
  }

  public void initialize(SecretKey key)
      throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
    encryptCipher = Cipher.getInstance("AES");
    encryptCipher.init(Cipher.ENCRYPT_MODE, key);

    decryptCipher = Cipher.getInstance("AES");
    decryptCipher.init(Cipher.DECRYPT_MODE, key);

    System.out.println("Symmetric Key loaded");
  }

  public String encryptText(String text) throws IllegalBlockSizeException, BadPaddingException {
    byte[] cipherText = encryptCipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(cipherText);
  }

  public String decryptText(String text) throws IllegalBlockSizeException, BadPaddingException {
    byte[] plainText = decryptCipher.doFinal(Base64.getDecoder().decode(text));
    return new String(plainText);
  }

  private String keyToString(Key key) {
    byte[] keyBytes = key.getEncoded();
    return Base64.getEncoder().encodeToString(keyBytes);
  }
}
