package br.com.crazycrowd.openssh;

import br.com.crazycrowd.openssh.decrypter.OpenSSHCipher;
import br.com.crazycrowd.openssh.kdf.OpenSSHKDFOptions;
import br.com.crazycrowd.openssh.kdf.OpenSSHKDFType;
import br.com.crazycrowd.openssh.keys.OpenSSHAsymmetricKeyType;

import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

public class OpenSSHKeyReader {

  private static final OpenSSHKeyReader keyReader = new OpenSSHKeyReader();
  private static final String AUTH_MAGIC = "openssh-key-v1";

  /**
   * Singleton class. Use `getInstance()`.
   */
  private OpenSSHKeyReader() {
  }

  public static OpenSSHKeyReader getInstance() {
    return keyReader;
  }

  /**
   * Reads an OpenSSH file and its multiple key pairs. This method could be
   * static, but its easier to mock an instance method (I have PowerMock).
   * <p>
   * Just describing the algorithm here (please, read PROTOCOL.key file
   * mentioned in README.md to understand this):
   * <p>
   * 1. I'll `overall format` declared section first
   * 2. Then, decryption configuration starts
   * 3. Finally, associate private keys with public keys and return
   *
   * @param filePath Path to OpenSSH key file
   * @return List of all key pairs declared inside specified file
   * @throws IOException In case there is a problem reading file.
   */
  public List<KeyPair> readFile(
      final Path filePath
  ) throws IOException, GeneralSecurityException {
    return readFile(filePath, null);
  }

  /**
   * Reads an OpenSSH file and its multiple key pairs. This method could be
   * static, but its easier to mock an instance method (I have PowerMock).
   * <p>
   * Just describing the algorithm here (please, read PROTOCOL.key file
   * mentioned in README.md to understand this):
   * <p>
   * 1. I'll `overall format` declared section first
   * 2. Then, decryption configuration starts
   * 3. Finally, associate private keys with public keys and return
   *
   * @param filePath   Path to OpenSSH key file
   * @param passphrase Passphrase to decrypt file. This passphrase bytes are
   *                   read with `getBytes()`, so do not use any weird
   *                   characters that could not translate with default charset
   * @return List of all key pairs declared inside specified file
   * @throws IOException In case there is a problem reading file.
   */
  public List<KeyPair> readFile(
      final Path filePath,
      final String passphrase
  ) throws IOException, GeneralSecurityException {
    final byte[] decodedKeyBytes =
        OpenSSHKeyFileParser.readFileBytesDecoded(filePath);

    return readBytes(decodedKeyBytes, passphrase);
  }

  /**
   * Process OpenSSH file bytes and returns its multiple key pairs.
   *
   * @param decodedBytes OpenSSH file bytes, without header and already Base64
   *                     decoded.
   * @param passphrase   Passphrase to decrypt file.
   * @return List of all key pairs declared in bytes
   */
  public List<KeyPair> readBytes(
      final byte[] decodedBytes,
      final String passphrase
  ) throws GeneralSecurityException {
    final ByteBuffer buf = ByteBuffer.wrap(decodedBytes);
    final String authMagic = ByteBufferUtils
        .readNextBytesAsString(buf, AUTH_MAGIC.length());

    if (!AUTH_MAGIC.equals(authMagic)) {
      throw new IllegalArgumentException("OpenSSH version does not match: " +
          "Expected " + AUTH_MAGIC + " | Found " + authMagic);
    }

    // Gets \0 terminator from OpenSSH version AUTH_MAGIC header
    // This is the only string with this terminator in this file
    if (buf.get() != '\0') {
      throw new IllegalBlockSizeException(
          "Terminator \\0 for AUTH_MAGIC not found"
      );
    }

    final OpenSSHCipher cipher = OpenSSHCipher
        .getFromAlgorithmString(ByteBufferUtils.readString(buf));

    final OpenSSHKDFType kdfType = OpenSSHKDFType
        .getFromKdfNameString(ByteBufferUtils.readString(buf));

    final OpenSSHKDFOptions kdfOptions = kdfType.kdf.readOptions(
        ByteBufferUtils.readStringBytes(buf)
    );

    final int numberKeys = buf.getInt();

    final List<PublicKey> publicKeys = readPublicKeys(
        ByteBufferUtils.readMultipleStringsAsBytes(buf, numberKeys)
    );

    final byte[] decryptedKeys = cipher.decrypter.decrypt(
        ByteBufferUtils.readStringBytes(buf),
        passphrase,
        kdfOptions,
        kdfType.kdf
    );

    final List<PrivateKey> privateKeys =
        readPrivateKeys(decryptedKeys, numberKeys);

    return matchPublicAndPrivateKeys(publicKeys, privateKeys);
  }

  private List<KeyPair> matchPublicAndPrivateKeys(
      final List<PublicKey> publicKeys,
      final List<PrivateKey> privateKeys
  ) {
    final List<KeyPair> keyPairs = new ArrayList<>(publicKeys.size());

    if (publicKeys.size() != privateKeys.size()) {
      throw new IllegalStateException(
          "Number of public and private keys do not match"
      );
    }

    for (int idx = 0; idx < publicKeys.size(); idx++) {
      keyPairs.add(new KeyPair(publicKeys.get(idx), privateKeys.get(idx)));
    }

    return keyPairs;
  }

  private List<PublicKey> readPublicKeys(
      final List<byte[]> keysBytes
  ) throws InvalidKeySpecException {
    final List<PublicKey> publicKeys = new ArrayList<>(keysBytes.size());

    for (byte[] keyBytes : keysBytes) {
      publicKeys.add(readPublicKey(keyBytes));
    }

    return publicKeys;
  }

  private PublicKey readPublicKey(
      final byte[] keyBytes
  ) throws InvalidKeySpecException {
    final ByteBuffer buf = ByteBuffer.wrap(keyBytes);

    return OpenSSHAsymmetricKeyType
        .getFromTypeNameString(ByteBufferUtils.readString(buf))
        .keyReader
        .readPublicKey(ByteBufferUtils.readStringBytes(buf));
  }

  private List<PrivateKey> readPrivateKeys(
      final byte[] decryptedKeysBytes,
      final int numKeys
  ) throws InvalidKeySpecException {
    final List<PrivateKey> privateKeys = new ArrayList<>(numKeys);
    final ByteBuffer buf = ByteBuffer.wrap(decryptedKeysBytes);

    if (buf.getInt() != buf.getInt()) {
      throw new RuntimeException(
          "Error decrypting key bytes: check integers do not match!"
      );
    }

    for (int idx = 0; idx < numKeys; idx++) {
      final OpenSSHAsymmetricKeyType keyType = OpenSSHAsymmetricKeyType
          .getFromTypeNameString(ByteBufferUtils.readString(buf));
      privateKeys.add(keyType.keyReader.readPrivateKey(buf));
    }

    return privateKeys;
  }

}
