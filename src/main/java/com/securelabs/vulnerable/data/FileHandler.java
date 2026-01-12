package com.securelabs.vulnerable.data;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;

/**
 * VULNERABLE: File Handler
 *
 * This file contains INTENTIONAL security vulnerabilities for training purposes.
 * DO NOT use these patterns in production code.
 *
 * Vulnerabilities:
 * - A01: Path Traversal in file operations
 * - A10: SSRF in URL fetching
 * - A08: Unsafe file type handling
 */
public class FileHandler {

    private static final String UPLOAD_DIR = "/var/www/uploads/";
    private static final String[] BLOCKED_EXTENSIONS = {".exe", ".bat"};

    /**
     * VULNERABLE: Path Traversal allows reading arbitrary files
     */
    public byte[] readFile(String filename) throws IOException {
        // VULNERABLE: No path validation - allows ../../../etc/passwd
        String fullPath = UPLOAD_DIR + filename;

        System.out.println("Reading file: " + fullPath);

        return Files.readAllBytes(Paths.get(fullPath));
    }

    /**
     * VULNERABLE: Path Traversal in file writing
     */
    public void writeFile(String filename, byte[] data) throws IOException {
        // VULNERABLE: Allows writing to arbitrary locations
        String fullPath = UPLOAD_DIR + filename;

        Files.write(Paths.get(fullPath), data);
    }

    /**
     * VULNERABLE: Incomplete extension blacklist
     */
    public boolean isAllowedFileType(String filename) {
        // VULNERABLE: Blacklist approach - misses .php, .jsp, .sh, etc.
        for (String blocked : BLOCKED_EXTENSIONS) {
            if (filename.toLowerCase().endsWith(blocked)) {
                return false;
            }
        }
        return true; // VULNERABLE: Allows all other extensions
    }

    /**
     * VULNERABLE: File type validation by extension only
     */
    public String getContentType(String filename) {
        // VULNERABLE: Extension can be spoofed
        if (filename.endsWith(".jpg") || filename.endsWith(".jpeg")) {
            return "image/jpeg";
        } else if (filename.endsWith(".png")) {
            return "image/png";
        } else if (filename.endsWith(".pdf")) {
            return "application/pdf";
        }
        return "application/octet-stream";
    }

    /**
     * VULNERABLE: SSRF - fetches arbitrary URLs
     */
    public byte[] fetchFromUrl(String urlString) throws Exception {
        // VULNERABLE: No URL validation - allows internal network access
        URL url = new URL(urlString);

        System.out.println("Fetching URL: " + urlString);

        // VULNERABLE: Follows redirects, no timeout, accesses any host
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setFollowRedirects(true);

        // VULNERABLE: No check for internal IP addresses
        // VULNERABLE: No protocol restriction (file://, ftp://, etc.)

        try (InputStream is = connection.getInputStream();
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }
            return baos.toByteArray();
        }
    }

    /**
     * VULNERABLE: SSRF with file protocol
     */
    public String readUrlContent(String urlString) throws Exception {
        // VULNERABLE: Allows file:// protocol
        URL url = new URL(urlString);

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            return content.toString();
        }
    }

    /**
     * VULNERABLE: Directory listing exposure
     */
    public List<String> listFiles(String directory) throws IOException {
        // VULNERABLE: Allows listing any directory
        String fullPath = UPLOAD_DIR + directory;

        File dir = new File(fullPath);
        String[] files = dir.list();

        // VULNERABLE: Exposes file structure
        return files != null ? Arrays.asList(files) : Collections.emptyList();
    }

    /**
     * VULNERABLE: Unsafe file deletion
     */
    public void deleteFile(String filename) throws IOException {
        // VULNERABLE: Path traversal allows deleting arbitrary files
        String fullPath = UPLOAD_DIR + filename;

        Files.deleteIfExists(Paths.get(fullPath));
        System.out.println("Deleted file: " + fullPath);
    }

    /**
     * VULNERABLE: Unsafe file move/rename
     */
    public void moveFile(String source, String destination) throws IOException {
        // VULNERABLE: Both paths are user-controlled
        Files.move(Paths.get(UPLOAD_DIR + source), Paths.get(UPLOAD_DIR + destination));
    }

    /**
     * VULNERABLE: Zip slip vulnerability
     */
    public void extractZip(String zipPath, String destDir) throws Exception {
        java.util.zip.ZipInputStream zis = new java.util.zip.ZipInputStream(
            new FileInputStream(UPLOAD_DIR + zipPath)
        );

        java.util.zip.ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            // VULNERABLE: No validation of entry name - allows ../
            String filePath = destDir + "/" + entry.getName();

            System.out.println("Extracting: " + filePath);

            if (!entry.isDirectory()) {
                Files.copy(zis, Paths.get(filePath));
            }
        }
        zis.close();
    }

    /**
     * VULNERABLE: Unsafe temp file creation
     */
    public File createTempFile(String prefix, String suffix) throws IOException {
        // VULNERABLE: Predictable temp file names
        String filename = prefix + System.currentTimeMillis() + suffix;
        return new File("/tmp/" + filename);
    }
}
