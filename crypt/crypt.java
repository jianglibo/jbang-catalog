///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.6.3
//DEPS org.json:json:20231013
//DEPS at.favre.lib:bcrypt:0.10.2

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCrypt.Result;
import at.favre.lib.crypto.bcrypt.BCrypt.Version;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

@Command(name = "crypt", subcommands = {
                crypt.Password.class }, mixinStandardHelpOptions = true, version = "crypt 0.1", description = "a crypt utility")
class crypt {

        // static String bigIntEncode(byte[] bytes) {
        // BigInteger bigInteger = new BigInteger(1, bytes);
        // return bigInteger.toString(16); // Convert to hexadecimal
        // }

        // static byte[] bigIntDecode(String hexString) {
        // BigInteger bigInteger = new BigInteger(hexString, 16);
        // return bigInteger.toByteArray();
        // }

        // static String encodeToHex(byte[] bytes) {
        // StringBuilder hexStringBuilder = new StringBuilder(2 * bytes.length);
        // for (byte b : bytes) {
        // hexStringBuilder.append(String.format("%02X", b));
        // }
        // return hexStringBuilder.toString();
        // }

        // static byte[] decodeFromHex(String hexString) {
        // int len = hexString.length();
        // byte[] result = new byte[len / 2];
        // for (int i = 0; i < len; i += 2) {
        // result[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
        // + Character.digit(hexString.charAt(i + 1), 16));
        // }
        // return result;
        // }

        private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

        public static String bytesToHex(byte[] bytes) {
                byte[] hexChars = new byte[bytes.length * 2];
                for (int j = 0; j < bytes.length; j++) {
                        int v = bytes[j] & 0xFF;
                        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
                        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
                }
                return new String(hexChars, StandardCharsets.UTF_8);
        }

        public static byte[] hex2Bytes(String hex) {
                byte[] bytes = new byte[hex.length() / 2];
                for (int i = 0; i < bytes.length; i++) {
                        int index = i * 2;
                        int j = Integer.parseInt(hex.substring(index, index + 2), 16);
                        bytes[i] = (byte) j;
                }
                return bytes;
        }

        // Method to convert SecretKey to String
        static String secretKeyToString(SecretKey secretKey) {
                byte[] encodedKey = secretKey.getEncoded();
                return Base64.getEncoder().encodeToString(encodedKey);
        }

        // Method to restore SecretKey from String
        static SecretKey stringToSecretKey(String keyString) {
                byte[] decodedKey = Base64.getDecoder().decode(keyString);
                // return new javax.crypto.spec.SecretKeySpec(decodedKey, 0, decodedKey.length,
                // Symmetric.AES);
                return new javax.crypto.spec.SecretKeySpec(decodedKey, Symmetric.AES);
        }

        @Spec
        CommandSpec spec;
        public static char[] passwordChars = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                        'o',
                        'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E',
                        'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
                        'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-',
                        '.', '_', '~' };

        public static void main(String... args) {
                int exitCode = new CommandLine(new crypt()).execute(args);
                System.exit(exitCode);
        }

        // Java program to generate
        // a symmetric key

        // Class to create a
        // symmetric key
        public static class Symmetric {

                public static final String AES = "AES";

                // We are using a Block cipher(CBC mode)
                private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5PADDING";

                // Function to create a secret key
                public static SecretKey createAESKey()
                                throws Exception {

                        // Creating a new instance of
                        // SecureRandom class.
                        SecureRandom securerandom = new SecureRandom();

                        // Passing the string to
                        // KeyGenerator
                        KeyGenerator keygenerator = KeyGenerator.getInstance(AES);

                        // Initializing the KeyGenerator
                        // with 256 bits.
                        keygenerator.init(256, securerandom);
                        SecretKey key = keygenerator.generateKey();
                        return key;
                }

                // Function to initialize a vector
                // with an arbitrary value
                public static byte[] createInitializationVector() {

                        // Used with encryption
                        byte[] initializationVector = new byte[16];
                        SecureRandom secureRandom = new SecureRandom();
                        secureRandom.nextBytes(initializationVector);
                        return initializationVector;
                }

                // This function takes plaintext,
                // the key with an initialization
                // vector to convert plainText
                // into CipherText.
                public static byte[] do_AESEncryption(
                                String plainText,
                                SecretKey secretKey,
                                byte[] initializationVector)
                                throws Exception {
                        Cipher cipher = Cipher.getInstance(
                                        AES_CIPHER_ALGORITHM);

                        IvParameterSpec ivParameterSpec = new IvParameterSpec(
                                        initializationVector);

                        cipher.init(Cipher.ENCRYPT_MODE,
                                        secretKey,
                                        ivParameterSpec);

                        return cipher.doFinal(
                                        plainText.getBytes());
                }

                // This function performs the
                // reverse operation of the
                // do_AESEncryption function.
                // It converts ciphertext to
                // the plaintext using the key.
                public static String do_AESDecryption(
                                byte[] cipherText,
                                SecretKey secretKey,
                                byte[] initializationVector)
                                throws Exception {
                        Cipher cipher = Cipher.getInstance(
                                        AES_CIPHER_ALGORITHM);

                        IvParameterSpec ivParameterSpec = new IvParameterSpec(
                                        initializationVector);

                        cipher.init(
                                        Cipher.DECRYPT_MODE,
                                        secretKey,
                                        ivParameterSpec);

                        byte[] result = cipher.doFinal(cipherText);

                        return new String(result);
                }

                // Driver code
                public static void main(String args[])
                                throws Exception {
                        SecretKey Symmetrickey = createAESKey();
                        System.out.println("Output");
                        System.out.print("The Symmetric Key is :"
                                        + bytesToHex(Symmetrickey.getEncoded()));
                }

        }

        @Command(mixinStandardHelpOptions = true, description = "decrypt string or file.")
        void decrypt(
                        @Parameters(description = "the string to decrypt", paramLabel = "<cipherTextOrFile>") String cipherText,
                        @Option(names = {
                                        "--password" }, description = "the password to decrypt", paramLabel = "password") String password,
                        @Option(names = {
                                        "--out" }, description = "the output file", paramLabel = "outfile", required = true) String outfile,
                        @Option(names = {
                                        "--isfile" }, description = "encrypt the file", paramLabel = "isfile") boolean isfile)
                        throws Exception {

                String script;
                if (isfile) {
                        script = """
                                        openssl enc -aes-256-cbc -d -a -salt -pbkdf2 -iter 100000 -in %s -out %s -pass pass:%s
                                        """;
                        script = String.format(script, cipherText, outfile, password);
                } else {
                        script = """
                                        echo '%s' | openssl enc -d -aes-256-cbc -a -salt -pbkdf2 -iter 100000 -pass pass:%s
                                        """;
                        script = String.format(script, cipherText, password);
                }
                MyLangUtil.runScript(script).stream().forEach(System.out::println);
                // SecretKey password = AESUtil.getKeyFromPassword("hello", "hello");
                // String decrypted = AESUtil.decryptPasswordBased(cipherText, password,
                // AESUtil.generateIv());
                // System.out.println(decrypted);
                // byte[] initializationVector = Symmetric.createInitializationVector();
                // // SecretKey skey = Symmetric.createAESKey();
                // SecretKey skey = stringToSecretKey(key);
                // System.out.println(
                // Symmetric.do_AESDecryption(cipherText.getBytes(), skey,
                // initializationVector));
        }

        @Command(mixinStandardHelpOptions = true, description = "encrypt string or file.")
        void encrypt(@Parameters(description = "the string to encrypt", paramLabel = "StringOrFile") String plainText,
                        @Option(names = {
                                        "--password" }, description = "the password to decrypt", paramLabel = "password") String password,
                        @Option(names = {
                                        "--out" }, description = "the output file", paramLabel = "outfile", required = true) String outfile,
                        @Option(names = {
                                        "--isfile" }, description = "encrypt the file", paramLabel = "isfile") boolean isfile)
                        throws Exception {
                boolean passwordGenerated = false;
                if (password == null || password.isBlank()) {
                        password = Password.userGenPass(16);
                        passwordGenerated = true;
                }
                String script;
                if (isfile) { // it's a file
                        script = """
                                        openssl enc -aes-256-cbc -a -salt -pbkdf2 -iter 100000 -in %s -out %s -pass pass:%s
                                        """;
                        script = String.format(script, plainText, outfile, password);
                } else {
                        script = """
                                        echo '%s' | openssl enc -aes-256-cbc -a -salt -pbkdf2 -iter 100000 -pass pass:%s
                                        """;
                        script = String.format(script, plainText, password);
                }

                // openssl enc -d -aes-256-cbc -a -salt -pbkdf2 -iter 100000 -in xx.xx.enc -out
                // xx.xx1 -pass pass:hello
                MyLangUtil.runScript(script).stream().forEach(System.out::println);
                if (passwordGenerated)
                        System.out.println(password);
                // SecretKey password = AESUtil.getKeyFromPassword("hello", "hello");
                // String encrypted = AESUtil.encryptPasswordBased(plainText, password,
                // AESUtil.generateIv());
                // System.out.println(encrypted);
                // byte[] initializationVector = Symmetric.createInitializationVector();
                // SecretKey symmetrickey = Symmetric.createAESKey();
                // System.out.println(
                // secretKeyToString(symmetrickey) + " " +
                // bytesToHex(
                // Symmetric.do_AESEncryption(plainText, symmetrickey,
                // initializationVector)));
        }

        @Command(name = "password", mixinStandardHelpOptions = true, version = "password 0.1", description = "password utility.")
        public static class Password {

                @Command(mixinStandardHelpOptions = true)
                void generate(
                                @Option(names = { "-l",
                                                "--length" }, description = "the length of the password", paramLabel = "<Length>", defaultValue = "32") Integer length) {
                        if (length > 72) {
                                length = 72;
                        }
                        String password = userGenPass(length);
                        String bcryptHashString = BCrypt
                                        .with(Version.VERSION_2Y)
                                        .hashToString(12, password.toCharArray());
                        System.out.println(password + " " + bcryptHashString);
                }

                @Command(mixinStandardHelpOptions = true)
                void verify(
                                @Parameters(description = "raw password", paramLabel = "<RawPassword>") String rawPassword,
                                @Parameters(description = "hashed password", paramLabel = "<HashedPassword>") String hashedPassword) {
                        Result result = BCrypt.verifyer(Version.VERSION_2Y)
                                        .verify(rawPassword.getBytes(), hashedPassword.getBytes());
                        System.out.println(result.verified);
                }

                public static String userGenPass(int length) {
                        return new SecureRandom()
                                        .ints(length, 0, passwordChars.length)
                                        .mapToObj(i -> passwordChars[i])
                                        .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                                        .toString();
                }

                // 65-90(upcase), 97-122(lowcase), 48-57(number)
                // "-" / "." / "_" / "~"

                String generateRandomPassword(int length) {
                        SecureRandom secureRandom = new SecureRandom();
                        byte[] keyBytes = new byte[length];
                        secureRandom.nextBytes(keyBytes);
                        return Base64.getEncoder().encodeToString(keyBytes);
                }

                String generateRandomPasswordBigInt(int length) {
                        SecureRandom secureRandom = new SecureRandom();
                        byte[] keyBytes = new byte[length];
                        secureRandom.nextBytes(keyBytes);
                        return bytesToHex(keyBytes);
                }

        }

        public static class AESUtil {

                public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv)
                                throws NoSuchPaddingException, NoSuchAlgorithmException,
                                InvalidAlgorithmParameterException,
                                InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
                        Cipher cipher = Cipher.getInstance(algorithm);
                        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
                        byte[] cipherText = cipher.doFinal(input.getBytes());
                        return Base64.getEncoder()
                                        .encodeToString(cipherText);
                }

                public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
                                throws NoSuchPaddingException, NoSuchAlgorithmException,
                                InvalidAlgorithmParameterException,
                                InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
                        Cipher cipher = Cipher.getInstance(algorithm);
                        cipher.init(Cipher.DECRYPT_MODE, key, iv);
                        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                                        .decode(cipherText));
                        return new String(plainText);
                }

                public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
                        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                        keyGenerator.init(n);
                        SecretKey key = keyGenerator.generateKey();
                        return key;
                }

                public static SecretKey getKeyFromPassword(String password, String salt)
                                throws NoSuchAlgorithmException, InvalidKeySpecException {
                        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
                        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                                        .getEncoded(), "AES");
                        return secret;
                }

                public static IvParameterSpec generateIv() throws NoSuchAlgorithmException {
                        byte[] iv = new byte[16];
                        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
                        // new SecureRandom().nextBytes(iv);
                        secureRandom.nextBytes(iv);
                        return new IvParameterSpec(iv);
                }

                public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
                                File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
                                NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
                                BadPaddingException, IllegalBlockSizeException {
                        Cipher cipher = Cipher.getInstance(algorithm);
                        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
                        FileInputStream inputStream = new FileInputStream(inputFile);
                        FileOutputStream outputStream = new FileOutputStream(outputFile);
                        byte[] buffer = new byte[64];
                        int bytesRead;
                        while ((bytesRead = inputStream.read(buffer)) != -1) {
                                byte[] output = cipher.update(buffer, 0, bytesRead);
                                if (output != null) {
                                        outputStream.write(output);
                                }
                        }
                        byte[] outputBytes = cipher.doFinal();
                        if (outputBytes != null) {
                                outputStream.write(outputBytes);
                        }
                        inputStream.close();
                        outputStream.close();
                }

                public static void decryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
                                File encryptedFile, File decryptedFile) throws IOException, NoSuchPaddingException,
                                NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
                                BadPaddingException, IllegalBlockSizeException {
                        Cipher cipher = Cipher.getInstance(algorithm);
                        cipher.init(Cipher.DECRYPT_MODE, key, iv);
                        FileInputStream inputStream = new FileInputStream(encryptedFile);
                        FileOutputStream outputStream = new FileOutputStream(decryptedFile);
                        byte[] buffer = new byte[64];
                        int bytesRead;
                        while ((bytesRead = inputStream.read(buffer)) != -1) {
                                byte[] output = cipher.update(buffer, 0, bytesRead);
                                if (output != null) {
                                        outputStream.write(output);
                                }
                        }
                        byte[] output = cipher.doFinal();
                        if (output != null) {
                                outputStream.write(output);
                        }
                        inputStream.close();
                        outputStream.close();
                }

                public static SealedObject encryptObject(String algorithm, Serializable object, SecretKey key,
                                IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
                                InvalidAlgorithmParameterException, InvalidKeyException, IOException,
                                IllegalBlockSizeException {
                        Cipher cipher = Cipher.getInstance(algorithm);
                        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
                        SealedObject sealedObject = new SealedObject(object, cipher);
                        return sealedObject;
                }

                public static Serializable decryptObject(String algorithm, SealedObject sealedObject, SecretKey key,
                                IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
                                InvalidAlgorithmParameterException, InvalidKeyException, ClassNotFoundException,
                                BadPaddingException, IllegalBlockSizeException, IOException {
                        Cipher cipher = Cipher.getInstance(algorithm);
                        cipher.init(Cipher.DECRYPT_MODE, key, iv);
                        Serializable unsealObject = (Serializable) sealedObject.getObject(cipher);
                        return unsealObject;
                }

                public static String encryptPasswordBased(String plainText, SecretKey key, IvParameterSpec iv)
                                throws NoSuchPaddingException, NoSuchAlgorithmException,
                                InvalidAlgorithmParameterException,
                                InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
                        return Base64.getEncoder()
                                        .encodeToString(cipher.doFinal(plainText.getBytes()));
                }

                public static String decryptPasswordBased(String cipherText, SecretKey key, IvParameterSpec iv)
                                throws NoSuchPaddingException, NoSuchAlgorithmException,
                                InvalidAlgorithmParameterException,
                                InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(Cipher.DECRYPT_MODE, key, iv);
                        return new String(cipher.doFinal(Base64.getDecoder()
                                        .decode(cipherText)));
                }

        }

        public static class MyLangUtil {
                private static Pattern argPattern = Pattern.compile("\"([^\"]*)\"|'([^']*)'|(\\S+)");

                public static List<String> runCmd(String cmd) throws IOException {
                        return new BufferedReader(new InputStreamReader(
                                        new ProcessBuilder(splitArgs(cmd))
                                                        .redirectErrorStream(true)
                                                        .start()
                                                        .getInputStream()))
                                        .lines().toList();
                }

                public static List<String> runScript(String script) throws IOException {
                        Process p = new ProcessBuilder("/bin/bash")
                                        .redirectErrorStream(true).start();
                        OutputStream os = p.getOutputStream();
                        os.write(script.getBytes(StandardCharsets.UTF_8));
                        os.flush();
                        os.close();
                        List<String> lines = new ArrayList<>();
                        try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                                String line;
                                while ((line = reader.readLine()) != null) {
                                        lines.add(line);
                                }
                        } catch (IOException e) {
                        }
                        return lines;
                }

                public static String[] splitArgs(String argsLine) {
                        Matcher matcher = argPattern.matcher(argsLine);
                        List<String> args = new ArrayList<>();

                        while (matcher.find()) {
                                if (matcher.group(1) != null) {
                                        args.add(matcher.group(1));
                                } else if (matcher.group(2) != null) {
                                        args.add(matcher.group(2));
                                } else {
                                        args.add(matcher.group(3));
                                }
                        }

                        // find last index of item which starts with - or -- in the args
                        int lastIndexOfOption = -1;
                        for (int i = args.size() - 1; i >= 0; i--) {
                                String arg = args.get(i);
                                if (arg.startsWith("-")) {
                                        lastIndexOfOption = i;
                                        break;
                                }
                        }
                        // if last index isn't the last second index, then combine all items behind the
                        // last index
                        if (lastIndexOfOption != -1 && lastIndexOfOption < args.size() - 2) {
                                int lastIndexOfValue = lastIndexOfOption + 1;
                                StringBuilder sb = new StringBuilder();
                                for (int i = lastIndexOfValue; i < args.size(); i++) {
                                        sb.append(args.get(i)).append(" ");
                                }
                                args.set(lastIndexOfValue, sb.toString().trim());
                                for (int i = args.size() - 1; i > lastIndexOfValue; i--) {
                                        args.remove(i);
                                }
                        }
                        return args.toArray(i -> new String[i]);
                }
        }

}
