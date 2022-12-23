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

package com.tenio.tool;

import com.tenio.tool.crypto.AesKeysHelper;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public final class AesKeysTest {

  public static void main(String[] args)
      throws NoSuchAlgorithmException, IOException,
      IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
    AesKeysHelper aesKeysHelper = new AesKeysHelper();

    aesKeysHelper.generateSymmetricKey("/Users/kong/Desktop/symmetric.key");

    SecretKey symmetric = aesKeysHelper.getKey("/Users/kong/Desktop/symmetric.key");

    aesKeysHelper.initialize(symmetric);

    String originText = "Hello World";
    System.out.println("Origin Text: " + originText);
    String encryptedText = aesKeysHelper.encryptText(originText);
    System.out.println("Encrypted Text: " + encryptedText);
    String decryptedText = aesKeysHelper.decryptText(encryptedText);
    System.out.println("Decrypted Text: " + decryptedText);
  }
}
