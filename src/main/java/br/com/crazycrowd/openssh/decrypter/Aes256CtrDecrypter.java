package br.com.crazycrowd.openssh.decrypter;

import br.com.crazycrowd.openssh.kdf.OpenSSHKDF;
import br.com.crazycrowd.openssh.kdf.OpenSSHKDFOptions;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

public class Aes256CtrDecrypter implements OpenSSHDecrypter {

  private static final Aes256CtrDecrypter decrypter = new Aes256CtrDecrypter();
  private static final int BYTES_FOR_KEY_AND_IV = 48;

  private Aes256CtrDecrypter() {
  }

  @Override
  public byte[] decrypt(
      final byte[] encrypted,
      final String passphrase,
      final OpenSSHKDFOptions kdfOptions,
      final OpenSSHKDF kdf
  ) throws GeneralSecurityException {
    final byte[] derivedKey = kdf.deriveKey(
        passphrase.getBytes(),
        kdfOptions.salt,
        kdfOptions.rounds,
        BYTES_FOR_KEY_AND_IV
    );

    final ByteBuffer keyAndIvBuffer = ByteBuffer.wrap(derivedKey);

    final byte[] keyBytes = new byte[32];
    final byte[] ivBytes = new byte[16];

    keyAndIvBuffer.get(keyBytes);
    keyAndIvBuffer.get(ivBytes);

    final SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
    final AlgorithmParameterSpec iv = new IvParameterSpec(ivBytes);

    final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

    return cipher.doFinal(encrypted);
  }

  public static Aes256CtrDecrypter getInstance() {
    return decrypter;
  }

}
