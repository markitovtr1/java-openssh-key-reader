package br.com.crazycrowd.openssh.keys;

import br.com.crazycrowd.openssh.ByteBufferUtils;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ED25519KeyReader implements OpenSSHAsymmetricKeyReader {

  private static final ED25519KeyReader instance = new ED25519KeyReader();
  private static final EdDSANamedCurveSpec CURVE_NAME =
      EdDSANamedCurveTable.getByName("Ed25519");

  private ED25519KeyReader() {
  }

  public static ED25519KeyReader getInstance() {
    return instance;
  }

  @Override
  public PublicKey readPublicKey(final byte[] publicKeyBytes) {
    final EdDSAPublicKeySpec publicSpec =
        new EdDSAPublicKeySpec(publicKeyBytes, CURVE_NAME);

    return new EdDSAPublicKey(publicSpec);
  }

  @Override
  public PrivateKey readPrivateKey(final ByteBuffer byteBuffer) {
    // Public key
    ByteBufferUtils.readStringBytes(byteBuffer);

    // Private + Public key bytes
    final ByteBuffer privateAndPublicKeyBytes = ByteBuffer.wrap(
        ByteBufferUtils.readStringBytes(byteBuffer)
    );

    final byte[] privateKeyBytes = new byte[32];
    privateAndPublicKeyBytes.get(privateKeyBytes);

    // Reading privateKey comment
    ByteBufferUtils.readString(byteBuffer);

    final EdDSAPrivateKeySpec keySpec =
        new EdDSAPrivateKeySpec(privateKeyBytes, CURVE_NAME);

    return new EdDSAPrivateKey(keySpec);
  }

}
