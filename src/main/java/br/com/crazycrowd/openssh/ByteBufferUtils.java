package br.com.crazycrowd.openssh;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Helper class to read some OpenSSH formats.
 */
public class ByteBufferUtils {

  private ByteBufferUtils() {
  }

  public static String readString(final ByteBuffer buf) {
    return readString(buf, StandardCharsets.UTF_8);
  }

  public static String readString(final ByteBuffer buf, final Charset cs) {
    final byte[] stringBytes = readStringBytes(buf);
    return new String(stringBytes, cs);
  }

  public static byte[] readStringBytes(final ByteBuffer buf) {
    final int length = buf.getInt();
    final byte[] stringBytes = new byte[length];
    buf.get(stringBytes);

    return stringBytes;
  }

  public static String readNextBytesAsString(
      final ByteBuffer buf,
      final int stringLength
  ) {
    final byte[] stringBytes = new byte[stringLength];
    buf.get(stringBytes);

    return new String(stringBytes);
  }

  public static List<byte[]> readMultipleStringsAsBytes(
      final ByteBuffer buf,
      final int numberStrings
  ) {
    final List<byte[]> stringsBytesList = new ArrayList<>(numberStrings);

    for (int idx = 0; idx < numberStrings; idx++) {
      stringsBytesList.add(readStringBytes(buf));
    }

    return stringsBytesList;
  }

}
