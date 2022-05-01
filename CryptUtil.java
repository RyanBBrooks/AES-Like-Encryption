package CryptUtil;

/**
 * Assignment 1: Ryan Brooks (u1115093)
 */

import java.io.*;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Random;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


public class CryptUtil {

    public static final int rounds = 8;

    public static final int[][] sbox = {{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

    public static final int[][] sbox_inv = {{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

    public static final int[][] exps_init = {{6,1,0,2,4,7,3,5},{5,1,3,0,6,7,4,2},{7,6,1,4,2,0,3,5},{1,7,6,3,0,5,4,2}};
    public static final int[][] exps_a = {{6,0,2,1,3,7,4,5},{3,5,1,7,6,2,0,4},{5,4,0,1,3,6,2,7},{4,3,5,1,2,7,6,0}};
    public static final int[][] exps_b = {{3,2,4,5,1,7,6,0},{0,7,1,4,3,2,5,6},{5,7,2,6,1,4,0,3},{3,1,5,4,7,6,0,2}};

    static byte[] iv_master = {(byte) 0x24,(byte) 0xe4,(byte) 0xfb,(byte) 0xb2,(byte) 0x36,(byte) 0x6c,(byte) 0xbb,(byte) 0xa8};

    public static final int[] exp8_1 = {25,16,55,11, 3,46,27,48,41,47,60,38, 4,15,40,17,13,57,19,21,53, 5, 8,37,18,34, 0, 7,61,59,26,39,23,51,33,14,36,20,43,63,10,28,44,22,12,31,58, 6,62,49,42,30, 2, 9,29,35,52,32, 1,50,24,45,54,56};
    public static final int[] exp8_2 = {3,20, 6,52,32,47,13,24,44, 2,45,58,28, 9,23,27,55, 7,15,26,42,25,37,31,57,61,40,53,39,35,56,30,41,60,19,43, 1,34,59,51,22,21,63, 0,50,48,10,29,49,18, 4,46,14,36, 8,54,11,38,17,33,12,16,62, 5};


    public static byte[] createSha1(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        InputStream fis = new FileInputStream(file);
        int n = 0;
        byte[] buffer = new byte[8192];
        while (n != -1) {
            n = fis.read(buffer);
            if (n > 0) {
                digest.update(buffer, 0, n);
            }
        }
        fis.close();
        return digest.digest();
    }

    public static boolean compareSha1(String filename1, String filename2) throws Exception {
        File file1 = new File(filename1);
        File file2 = new File(filename2);
        byte[] fsha1 = CryptUtil.createSha1(file1);
        byte[] fsha2 = CryptUtil.createSha1(file2);
        return Arrays.equals(fsha1, fsha2);
    }

    public static double getShannonEntropy(String s) {
        int n = 0;
        Map<Character, Integer> occ = new HashMap<>();

        for (int c_ = 0; c_ < s.length(); ++c_) {
            char cx = s.charAt(c_);
            if (occ.containsKey(cx)) {
                occ.put(cx, occ.get(cx) + 1);
            } else {
                occ.put(cx, 1);
            }
            ++n;
        }

        double e = 0.0;
        for (Map.Entry<Character, Integer> entry : occ.entrySet()) {
            char cx = entry.getKey();
            double p = (double) entry.getValue() / n;
            e += p * log2(p);
        }
        return -e;
    }

    public static double getShannonEntropy(byte[] data) {

        if (data == null || data.length == 0) {
            return 0.0;
        }

        int n = 0;
        Map<Byte, Integer> occ = new HashMap<>();

        for (int c_ = 0; c_ < data.length; ++c_) {
            byte cx = data[c_];
            if (occ.containsKey(cx)) {
                occ.put(cx, occ.get(cx) + 1);
            } else {
                occ.put(cx, 1);
            }
            ++n;
        }

        double e = 0.0;
        for (Map.Entry<Byte, Integer> entry : occ.entrySet()) {
            byte cx = entry.getKey();
            double p = (double) entry.getValue() / n;
            e += p * log2(p);
        }
        return -e;
    }

    public static double getFileShannonEntropy(String filePath) {
        try {
            byte[] content;
            content = Files.readAllBytes(Paths.get(filePath));
            return CryptUtil.getShannonEntropy(content);
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }

    }

    private static double log2(double a) {
        return Math.log(a) / Math.log(2);
    }

    public static void doCopy(InputStream is, OutputStream os) throws IOException {
        byte[] bytes = new byte[64];
        int numBytes;
        while ((numBytes = is.read(bytes)) != -1) {
            os.write(bytes, 0, numBytes);
        }
        os.flush();
        os.close();
        is.close();
    }

    public static Byte randomKey() {
        int leftLimit = 48; // numeral '0'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = 8;
        Random random = new Random();
        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
        return generatedString.getBytes()[0];
    }

    public static byte SboxRepl(byte b, boolean inv){
        int col = b & 0x0F; // col number for sbox
        int row = (b & 0xF0) >> 4; // row number for sbox
        //replace with sbox value
        if(inv){
            return (byte) sbox_inv[row][col];
        }
        else {
            return (byte) sbox[row][col];
        }
    }

    /**
     * turns one byte input key into nine, eight byte output keys
     *
     * Operations (simplified)
     *
     * 1. (1x 1 byte key -> 3x 1 byte keys)
     *      a. re-order based on order layed out by exps_init
     *      b. shift bits 3 different lengths and save each shifted  key
     *      c. re-order each based on order of exps_a
     *
     * 2. repeat 3 times, (3x 1 byte keys -> 9x 1 byte keys), throw one away... For each of the 3 1 byte keys:
     *      a. re-order based on order layed out by exps_init
     *      b. shift bits 3 different lengths and save each shifted key
     *      c. re-order each based on order of exps_b
     *      d. ultimately, results in nine keys, throw one away
     *
     * 3. 8byte large key -> 9x 8byte large keys
     *      a. re-order based on order in exp8_1
     *      b. shift bits by 9 different lengths and save each shifted key
     *      c. re-order based on order in exp8_2
     *      d. results in 9, 8 byte keys
     *
     * @param key
     * @return byte[][], 9x 8-byte keys
     */
    public static byte[][] KeyExpansion(byte key) {
        //First Step one byte -> eight bytes
        //convert key to bits array
        int[] bits = ByteToBits(key);
        //generate 3 keys using exp_a, put them in preKeys array
        int[][] preKeys = ByteExpansionHelper(bits, exps_a);
        //allocate 8 byte starter key
        byte[] eightByte = new byte[8];
        //generate 3 keys from each of the preKeys, combine them to make eight byte key
        for(int i=0; i<3; i++){
            int[][] keys = ByteExpansionHelper(preKeys[i], exps_b);
            for(int j=0; j<3; j++){
                //skip last key we only need 8
                if(i==2 && j==2){
                    continue;
                }
                eightByte[i*3+j] = BitsToByte(keys[j]);
            }
        }

        //Second Step nine bytes -> 9 x eight bytes
        //separate key into bits and re-arrange bits according to exp9_1
        int[] nineByteBits = ByteArrayToBits(eightByte);
        ReArrangeBits(nineByteBits, exp8_1);
        //shift by 7,7,7,9,7,9,9,7  bits and record
        int[] shifts = {7,6,7,7,7,6,6,7,7};
        int[][] expKeys = new int[9][64];
        //for each desired key
        for(int i=0; i<9; i++){
            //for each bit, shift
            int[] keyShift = nineByteBits.clone();
            for(int j=0; j<64; j++){
                nineByteBits[j] = keyShift[(j+shifts[i])%64];
            }
            expKeys[i] = nineByteBits.clone();
        }
        //separate key into bits and re-arrange bits according to exp argument
        byte[][] returnKeys = new byte[9][8];
        for(int i=0; i<9; i++){
            returnKeys[i] = BitsToByteArray(ReArrangeBits(expKeys[i], exp8_2));
        }
        return returnKeys;
    }

    //turns one input key into 3 output keys using exp
    public static int[][] ByteExpansionHelper(int[] key, int[][] exps) {
        //separate key into bits and re-arrange bits according to exp_init
        int[] exp = exps_init[Math.abs(BitsToByte(key)% exps_init.length)];
        int[] k = ReArrangeBits(key, exp);
        //shift by 2, 5, and 7 bits and record
        int[][] expKeys = new int[3][8];
        expKeys[0] = new int[]{k[2],k[3],k[4],k[5],k[6],k[7],k[0],k[1]};
        expKeys[1] = new int[]{k[5],k[6],k[7],k[0],k[1],k[2],k[3],k[4]};
        expKeys[2] = new int[]{k[7],k[0],k[1],k[2],k[3],k[4],k[5],k[6]};
        //separate key into bits and re-arrange bits according to exp argument
        for(int i=0; i<3; i++){
            exp = exps[Math.abs(BitsToByte(expKeys[i])%exps.length)];
            expKeys[i] = ReArrangeBits(expKeys[i],exp);
        }
        return expKeys;
    }
    //re-arrange bits of a key based on the positions described by passed in exp
    public static int[] ReArrangeBits(int[] bits, int[] exp){
        //re-arrange bits based on exp
        int[] tmp = new int[bits.length];
        for(int i=0; i<bits.length; i++){
            tmp[i] = bits[exp[i]];
        }
        return tmp;
    }

    //separate byte key into array of int bits
    public static int[] ByteToBits(Byte b){
        int[] bits = new int[8];
        for(int i=0; i<8; i++){
            bits[i] = (b >> i) & 1;
        }
        return bits;
    }

    //combine array of into bits into byte key
    public static Byte BitsToByte(int[] bits){
        int b = 0;
        for(int i=0; i<8; i++){
            b ^= (bits[i] << i) ;
        }
        return (byte) b;
    }

    //separate byte key array into array of int bits
    public static int[] ByteArrayToBits(byte[] bytes){
        int[] bits = new int[8*bytes.length];
        for(int j=0; j<bytes.length; j++) {
            for (int i = 0; i < 8; i++) {
                bits[j*8+i] = (bytes[j] >> i) & 1;
            }
        }
        return bits;
    }

    //combine array of into bits into byte key array
    public static byte[] BitsToByteArray(int[] bits){
        byte[] bytes = new byte[bits.length/8];
        for (int i = 0; i < bits.length; i++) {
            bytes[i/8] ^= (bits[i] << i%8);
        }
        return bytes;
    }

    public static void AddKey(byte[] key, byte[][] mat){
        for(int i=0; i<3; i++){
            for(int j=0; j<mat[i].length; j++){
                mat[i][j] ^= key[i*3+j];
            }
        }
    }

    /**
     * Encryption (Bytes)
     *
     * Encryption Steps
     *
     * 1. Takes 8 byte data and puts it into a 3x(3,3,2)  matrix in row major order
     *
     * 2. Expands 8 bit key using advanced key expansion algorithm into nine 8-byte keys
     *
     * 3. For 8 rounds
     *
     *      d. adds the round key (7-0) to the matrix (via XOR)
     *
     *      c. does new inverse half-byte shifting algorithm
     *
     *          I. splits bytes in half into two matricies l and r (4 bits per index)
     *
     *          II. shuffles l by shifting columns (shifted in inverse direction of encrypt)
     *
     *          III. shuffles r by swapping indexes across a horizontal axis
     *
     *          IIII. recombines l and r half-bytes into bytes
     *
     *      b. does inverse row shifting similar to AES but with a 3x(3,3,2) matrix
     *
     *      a. does inverse byte substitution with the sbox inverse table just like AES
     *
     *      e. repeat
     *
     * 4. Finally adds the last key (keys[8]) to the data matrix (via XOR)
     *
     * 5. Transforms matrix into data array by converting to column major order (reversion encryption order change) which is returned
     *
     * @param data
     * @param key
     * @return encrypted bytes
     */
    public static byte[] cs4440Encrypt(byte[] data, Byte key) {
        //construct matrix from data
        byte[][] mat = new byte[][]{new byte[]{data[0], data[3], data[6]},
                new byte[]{data[1], data[4], data[7]},
                new byte[]{data[2], data[5],}};

        byte[][] keys = KeyExpansion(key);
        AddKey(keys[8], mat);

        //do round operations
        for(int round=0; round<rounds; round++){

            //byte substitution
            for(int i=0;i<3;i++){
                for(int j=0;j<mat[i].length;j++){
                    mat[i][j] = SboxRepl(mat[i][j], false);

                }
            }

            //shift rows
            mat = new byte[][]{ new byte[]{mat[0][2], mat[0][0], mat[0][1]},
                    new byte[]{mat[1][1], mat[1][2], mat[1][0]},
                    new byte[]{mat[2][0], mat[2][1]}};

            // ! new operation shift half bytes !
            // separate into two matricies
            byte[][] l = new byte[][]{new byte[3], new byte[3], new byte[2]};
            byte[][] r = new byte[][]{new byte[3], new byte[3], new byte[2]};
            for(int i=0;i<3;i++){
                for(int j=0;j<mat[i].length;j++){
                    l[i][j] = (byte) (mat[i][j] & 0xF0);
                    r[i][j] = (byte) (mat[i][j] & 0x0F);
                }
            }
            //shift matricies l and r
            l = new byte[][]{   new byte[]{l[1][0], l[2][1], l[0][2]},
                    new byte[]{l[2][0], l[0][1], l[1][2]},
                    new byte[]{l[0][0], l[1][1]}};

            r = new byte[][]{   new byte[]{r[0][0], r[1][0], r[2][0]},
                    new byte[]{r[0][1], r[1][1], r[2][1]},
                    new byte[]{r[0][2], r[1][2], }};

            //recombine matricies
            for(int i=0;i<3;i++){
                for(int j=0;j<mat[i].length;j++){
                    mat[i][j] = (byte) (l[i][j] ^ r[i][j]);
                }
            }
            //round key
            AddKey(keys[round], mat);
        }
        //construct ciperdata from matrix
        byte[] cipherdata = new byte[]{mat[0][0], mat[0][1], mat[0][2], mat[1][0], mat[1][1], mat[1][2], mat[2][0], mat[2][1]};
        return cipherdata;
    }

    /**
     * Encryption (file)
     *
     * 1. Store all bytes from the file into an array of bytes
     *
     * 2. Calculate the length of the expected data by determining padding
     *
     * 3. for every 8 bytes
     *
     *      a. copy them over to a temporary byte array
     *
     *          - if we extend beyond the input array, each byte is the length of the padding
     *
     *      c. encrpypt: input data XORed with previous cipherdata (starting with iv)
     *
     *      d. store encrypted bytes to a holding byte[], update iv to be encrpyted bytes
     *
     * 4. Write data to output file
     *
     * @param plainfilepath
     * @param cipherfilepath
     * @param key
     */
    public static int encryptDoc(String plainfilepath, String cipherfilepath, Byte key) {
        try {
            //encrypt data first
            //initial vector
            //TODO: Setup IV
            byte[] iv = iv_master.clone();
            //set up file
            File in;
            in = new File(plainfilepath);
            byte[] allBytes = Files.readAllBytes(in.toPath());
            //setup output array
            byte[] encrypted = new byte[(allBytes.length/8)*8+8];
            //for every byte, incrementing by 8
            for(int i=0; i<encrypted.length;i+=8){
                //encrypt bytes
                byte[] data = new byte[8];
                boolean padFound = false;
                int pad = 0;
                for(int j=0; j<8; j++){
                    //data
                    if(j+i<allBytes.length){
                        data[j] = allBytes[i+j];
                    }
                    //padding
                    else{
                        if(!padFound) {
                            pad = 8-j;
                            padFound = true;
                        }
                        data[j] = (byte) pad;
                    }
                }
                // xor data with last ciphertext
                iv = cs4440Encrypt(XORArray(data,iv), key);
                // put it into output (encrypted)
                for(int j=0; j<8; j++){
                    encrypted[i+j] = iv[j];
                }
            }
            //write encrypted data
            Path out = Paths.get(cipherfilepath);
            if(Files.exists(out)) {
                Files.delete(out);
            }
            Files.write(out,encrypted,StandardOpenOption.CREATE);
        }
        catch(Exception e){
            return -1;
        }
        return 0;
    }

    public static byte[] XORArray(byte[] a, byte[] b){
        byte[] c = new byte[a.length];
        for(int i=0; i<a.length; i++){
            c[i] = (byte) (a[i] ^ b[i]);
        }
        return c;
    }

    /**
     * Decryption (Bytes)
     *
     * Decrytion Steps
     *
     * 1. Takes 8 byte cipherdata and puts it into a 3x(3,3,2) matrix in column major order appending 0xFF for the final byte
     *
     * 2. Expands 8 bit key using advanced key expansion algorithm into nine 8-byte keys
     *
     * 3. Initially adds the last key (keys[8]) to the data matrix (via XOR)
     *
     * 4. For 8 rounds
     *
     *      a. does byte substitution with the sbox table just like AES
     *
     *      b. does row shifting similar to AES but with a 3x(3,3,2) matrix
     *
     *      c. does new half-byte shifting algorithm
     *
     *          I. splits bytes in half into two matricies l and r (4 bits per index)
     *
     *          II. shuffles l by shifting columns (similar to row shift but only with half of each byte)
     *
     *          III. shuffles r by swapping indexes across a horizontal axis
     *
     *          IIII. recombines l and r half-bytes into bytes
     *
     *      d. adds current key (0-7) to the matrix (via XOR)
     *
     *      e. repeat
     *
     * 5. Transforms matrix into cipherdata array which is returned
     *
     * @param data
     * @param key
     * @return decrypted content
     */

    public static byte[] cs4440Decrypt(byte[] data, Byte key) {
        //construct matrix from data
        byte[][] mat =  new byte[][]{new byte[]{data[0], data[1], data[2]}, new byte[]{data[3], data[4], data[5]}, new byte[]{data[6], data[7]}};

        //key generation
        byte[][] keys = KeyExpansion(key);

        //do round operations
        for(int round=0; round<rounds; round++){

            //add round key
            AddKey(keys[7-round], mat);

            // ! new operation inverse shift half bytes !
            // separate into two matricies
            byte[][] l = new byte[3][3];
            byte[][] r = new byte[3][3];
            for(int i=0;i<3;i++){
                for(int j=0;j<mat[i].length;j++){
                    l[i][j] = (byte) (mat[i][j] & 0xF0);
                    r[i][j] = (byte) (mat[i][j] & 0x0F);
                }
            }
            //shift matricies l and r
            l = new byte[][]{new byte[]{l[2][0], l[1][1], l[0][2]},
                    new byte[]{l[0][0], l[2][1], l[1][2]},
                    new byte[]{l[1][0], l[0][1]}};

            r = new byte[][]{   new byte[]{r[0][0], r[1][0], r[2][0]},
                    new byte[]{r[0][1], r[1][1], r[2][1]},
                    new byte[]{r[0][2], r[1][2], }};

            //recombine matricies
            for(int i=0;i<3;i++){
                for(int j=0;j<mat[i].length;j++){
                    mat[i][j] = (byte) (l[i][j] ^ r[i][j]);
                }
            }

            //inverse shift rows
            mat = new byte[][]{ new byte[]{mat[0][1], mat[0][2], mat[0][0]},
                    new byte[]{mat[1][2], mat[1][0], mat[1][1]},
                    new byte[]{mat[2][0], mat[2][1]}};

            //byte substitution inverse
            for(int i=0;i<3;i++){
                for(int j=0;j<mat[i].length;j++){
                    mat[i][j] = SboxRepl(mat[i][j], true);
                }
            }
        }

        //add pre rounds key
        AddKey(keys[8], mat);

        //construct ciperdata from matrix
        byte[] plaindata = new byte[]{  mat[0][0], mat[1][0], mat[2][0],
                mat[0][1], mat[1][1], mat[2][1],
                mat[0][2], mat[1][2]};
        return plaindata;
    }

    /**
     * Decryption (file)
     *
     * 1. Store all bytes from the input file into an array of bytes
     *
     * 2. gather first 8 bits of prevcipherdata
     *
     * 3. loop over the rest of the cipherdata looking at each 8 bytes
     *
     *    a. plain data = prevcipherdata ^ decrypt(cipherdata key)                    prevcipherdata = cipherdata
     *
     *    b. the first pass will decrypt the block with the padding, throw away padding and set size of output
     *
     *    c. save data to byte[] for writing to file
     *
     * 4. do a final pass of decryption, XORing with the iv
     *
     * 5. Write bytes to output file
     *
     * @param plainfilepath
     * @param cipherfilepath
     * @param key
     */
    public static int decryptDoc(String plainfilepath, String cipherfilepath, Byte key) {
        try {
            //decrypt data first
            //initial vector
            //TODO: SETUP IV
            byte[] iv = iv_master.clone();
            byte[] prevcipherdata = new byte[8];
            //set up file
            File in;
            in = new File(plainfilepath);
            byte[] allBytes = Files.readAllBytes(in.toPath());

            //determine padding
            int allBytesLen = allBytes.length;
            boolean depadded = false;
            //setup output array
            byte[] decrypted = new byte[8];

            //initialize decryption data
            byte[] cipherdata = new byte[8];
            for(int j=0; j<8; j++){
                cipherdata[7-j] = allBytes[allBytesLen-j-1];
            }

            byte[] data = new byte[8];
            //for every byte, decrementing from te end by 8
            for(int i=allBytesLen-9; i>=7;i-=8){
                for(int j=0; j<8; j++){
                    prevcipherdata[7-j] = allBytes[i-j];
                }
                //decrpyt
                data = XORArray(prevcipherdata, cs4440Decrypt(cipherdata, key));
                //copy cipherdata
                cipherdata = prevcipherdata.clone();
                // put it into output (encrypted)
                int j = 0;
                //depad if we haven't
                if(!depadded){
                    int pad = (int) data[7];
                    j = pad;
                    //set decrpyted length;
                    decrypted = new byte[allBytesLen-pad];
                    depadded = true;
                }
                for(;j<8; j++){
                    decrypted[i-j+8] = data[7-j];
                }
            }
            //do final pass with iv
            data = XORArray(iv, cs4440Decrypt(cipherdata, key));
            for(int j=0; j<8; j++){
                decrypted[7-j] = data[7-j];
            }

            //write decrypted data
            Path out = Paths.get(cipherfilepath);
            if(Files.exists(out)) {
                Files.delete(out);
            }
            Files.write(out,decrypted,StandardOpenOption.CREATE);
        }
        catch(java.io.IOException e){
            return -1;
        }
        return 0;
    }

    public static void main(String[] args) {

        String targetFilepath = "";
        String encFilepath = "";
        String decFilepath = "";
        if (args.length == 3) {
            try {
                File file1 = new File(args[0].toString());
                if (file1.exists() && !file1.isDirectory()) {
                    targetFilepath = args[0].toString();
                } else {
                    System.out.println("File does not exist!");
                    System.exit(1);
                }

                encFilepath = args[1].toString();
                decFilepath = args[2].toString();
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }
        } else {
            // targetFilepath = "cs4440-a1-testcase1.html";
            System.out.println("Usage: java CryptoUtil file_to_be_encrypted encrypted_file decrypted_file");
            System.exit(1);
        }

        Byte key = randomKey();
        String src = "ABCDEFGH";
        System.out.println("[*] Now testing plain sample： " + src);
        try {
            byte[] encrypted = CryptUtil.cs4440Encrypt(src.getBytes(), key);
            StringBuilder encsb = new StringBuilder();
            for (byte b : encrypted) {
                encsb.append(String.format("%02X ", b));
            }
            System.out.println("[*] The  encrypted sample  [Byte Format]： " + encsb);
            double entropyStr = CryptUtil.getShannonEntropy(encrypted.toString());
            System.out.printf("[*] Shannon entropy of the text sample (to String): %.12f%n", entropyStr);
            double entropyBytes = CryptUtil.getShannonEntropy(encrypted);
            System.out.printf("[*] Shannon entropy of encrypted message (Bytes): %.12f%n", entropyBytes);

            byte[] decrypted = CryptUtil.cs4440Decrypt(encrypted, key);
            if (Arrays.equals(decrypted, src.getBytes())){
                System.out.println("[+] It works!  decrypted ： " + decrypted);
            } else {
                System.out.println("Decrypted message does not match!");
            }

            // File Encryption
            System.out.printf("[*] Encrypting target file: %s \n", targetFilepath);
            System.out.printf("[*] The encrypted file will be: %s \n", encFilepath);
            System.out.printf("[*] The decrypted file will be: %s \n", decFilepath);

            CryptUtil.encryptDoc(targetFilepath, encFilepath, key);
            CryptUtil.decryptDoc(encFilepath, decFilepath, key);

            System.out.printf("[+] [File] Entropy of the original file: %s \n",
                    CryptUtil.getFileShannonEntropy(targetFilepath));
            System.out.printf("[+] [File] Entropy of encrypted file: %s \n",
                    CryptUtil.getFileShannonEntropy(encFilepath));

            if (CryptUtil.compareSha1(targetFilepath, decFilepath)) {
                System.out.println("[+] The decrypted file is the same as the source file");
            } else {
                System.out.println("[+] The decrypted file is different from the source file.");
                System.out.println("[+] $ cat '<decrypted file>' to to check the differences");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
