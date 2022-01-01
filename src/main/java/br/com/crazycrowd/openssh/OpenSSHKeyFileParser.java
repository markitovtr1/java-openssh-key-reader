package br.com.crazycrowd.openssh;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;

public class OpenSSHKeyFileParser {

  private OpenSSHKeyFileParser() {
  }

  /**
   * Reads an OpenSSH file into memory and decodes its base64 string into
   * bytes.
   *
   * @param filePath OpenSSH file path
   * @return Decoded byte array of file content
   * @throws IOException In case there is a problem reading file.
   */
  static byte[] readFileBytesDecoded(final Path filePath) throws IOException {
    final List<String> lines = Files.readAllLines(filePath);

    final StringBuilder sb = new StringBuilder();

    for (final String line : lines) {
      if (!line.startsWith("-")) {
        sb.append(line);
      }
    }

    return Base64.getDecoder().decode(sb.toString());
  }

}
