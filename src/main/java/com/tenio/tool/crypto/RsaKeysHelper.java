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

import com.google.common.io.BaseEncoding;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RsaKeysHelper {

  private Cipher encryptCipher;
  private Cipher decryptCipher;

  public void generateKeyPair(String publicKeyName, String privateKeyName)
      throws NoSuchAlgorithmException, IOException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair pair = generator.generateKeyPair();

    PrivateKey privateKey = pair.getPrivate();
    PublicKey publicKey = pair.getPublic();

    try (FileOutputStream fos = new FileOutputStream(publicKeyName)) {
      fos.write(publicKey.getEncoded());
    }
    try (FileOutputStream fos = new FileOutputStream(privateKeyName)) {
      fos.write(privateKey.getEncoded());
    }

    System.out.println("Generated a pair of keys: " + publicKeyName + " | " + privateKeyName);
    System.out.println("PublicKey: " + keyToString(publicKey));
    System.out.println("PrivateKey: " + keyToString(privateKey));
  }

  public PublicKey getPublicKey(String keyPath)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    File publicKeyFile = new File(keyPath);
    byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
    return keyFactory.generatePublic(publicKeySpec);
  }

  public PrivateKey getPrivateKey(String keyPath)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    File privateKeyFile = new File(keyPath);
    byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    return keyFactory.generatePrivate(privateKeySpec);
  }

  public void initialize(PublicKey publicKey, PrivateKey privateKey, Runnable initialAction)
      throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
    if (publicKey != null) {
      encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
    }

    if (privateKey != null) {
      decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
    }

    initialAction.run();
  }

  public String encryptText(String text) throws IllegalBlockSizeException, BadPaddingException {
    byte[] cipherText = encryptCipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
    return BaseEncoding.base64().encode(cipherText);
  }

  public String decryptText(String text) throws IllegalBlockSizeException, BadPaddingException {
    byte[] plainText = decryptCipher.doFinal(BaseEncoding.base64().decode(text));
    return new String(plainText);
  }

  private String keyToString(Key key) {
    byte[] keyBytes = key.getEncoded();
    return BaseEncoding.base64().encode(keyBytes);
  }
}
