/*
 * The Data Encryption Standard (DES), known as the Data Encryption Algorithm (DEA)
 * by ANSI and the DEA-1 by the ISO, has been a worldwide standard for 20 years.
 * Although it is showing signs of old age, it has held up remarkably well against
 * years of cryptanalysis and is still secure against all  but possibly the most
 * powerful of adversaries.
 */
package block_ciphers;

import java.io.*;

/**
 * A modest implementation of DES cryptosystem.
 * <p>
 * @author Yoni Kilzi & Nimrod Shlagman
 */
public class DES_Cipher {

	private static long block;

	private static int op_code;

	private static int mode; // TODO

	private static int format; // TODO

	private static File inFile, outFile, kFile;

	private static RandomAccessFile keyFile, plaintextFile, outputFile;

	private static long[] subKeys;

	private static final byte[] IP = {
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7};

	private static final byte[] IPINV = {
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25};

	private static final byte[] PC1 = {
		57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4};

	private static final byte[] PC2 = {
		14, 17, 11, 24, 1, 5, 3,
		28, 15, 6, 21, 10, 23, 19,
		12, 4, 26, 8, 16, 7, 27,
		20, 13, 2, 41, 52, 31, 37,
		47, 55, 30, 40, 51, 45, 33,
		48, 44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32};

	private static final byte[] E_BOX = {
		32, 1, 2, 3, 4, 5,
		4, 5, 6, 7, 8, 9,
		8, 9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32, 1};

	private static final byte[][][] S_BOX = {
		{ // S1
			{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
			{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
			{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
			{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
		},
		{ // S2
			{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
			{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
			{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
			{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
		},
		{ // S3
			{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
			{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
			{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
			{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
		},
		{ // S4
			{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
			{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
			{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
			{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
		},
		{ // S5
			{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
			{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
			{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
			{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
		},
		{ // S6
			{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
			{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
			{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
			{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
		},
		{ // S7
			{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
			{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
			{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
			{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
		},
		{ // S8
			{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
			{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
			{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
			{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
		}};

	private static final byte[] P = {
		16, 7, 20, 21,
		29, 12, 28, 17,
		1, 15, 23, 26,
		5, 18, 31, 10,
		2, 8, 24, 14,
		32, 27, 3, 9,
		19, 13, 30, 6,
		22, 11, 4, 25
	};

	public static void main(String[] args) {

		// Check # of arguments
		if (args.length < 3) {
			System.out.println(
				"Usage: java DES_Cipher input output key (encrypt|decrypt)\n");
		}

		// Init
		inFile = new File(args[0]);
		outFile = new File(args[1]);
		kFile = new File(args[2]);

		// Check operation mode
		switch (args[3]) {
			case "encrypt":
				op_code = 1;
				break;
			case "decrypt":
				op_code = 2;
				break;
			case "verify":
				op_code = 3;
				break;
			default:
				System.err.println("Invalid Operation mode!\n"
					+ "Valid options are: encrypt|decrypt|verify");
				throw new AssertionError();
		}

		try {

			// STAGE #1 - Key Scheduler
			long key = readKey(kFile);
			System.out.printf("Key: 0x%016x\n", key);
			long pk = permutate(key, PC1);
			int c_0 = getLowerBits(28, pk);
			int d_0 = getHigherBits(28, pk);
			generateKeys(c_0, d_0);
			//debugKeys(); // TODO: add some debug flag / CLi arg.

			int count = 0;
			while (readBlock(inFile) != -1) {

				// STAGE #2 - Encryption Algo.
				System.out.printf("Block %2d: 0x%016x ", ++count, block);
				long ip = permutate(block, IP);
				int l_0 = getLowerBits(32, ip);
				int r_0 = getHigherBits(32, ip);

				// STAGE #3 - 16 Rounds
				int l_next = 0, l_prev = l_0;
				int r_next = 0, r_prev = r_0;
				for (int i = 1, k; i <= 16; i++) {
					k = (op_code == 1) ? i - 1 : 16 - i; // TODO: What if op_code == 3?
					l_next = r_prev;
					r_next = l_prev ^ f(r_prev, subKeys[k]);

					// Update next halves
					l_prev = l_next;
					r_prev = r_next;
				}
				long result = exchange(l_next, r_next);
				result = permutate(result, IPINV);

				// display the processed 64bit block
				System.out.printf("--> 0x%016x\n", result);
				writeBlock(outFile, result);

			}
			plaintextFile.close();
			outputFile.close();

		} catch (FileNotFoundException ex) {
			System.err.println(ex.getMessage());
		} catch (IOException ex) {
			System.err.println(ex.getMessage());
		}

	}

	/**
	 * Utility method used to properly perform selection/permutation of the bits
	 * specified by the given table.
	 * <p>
	 * @param v     - the input word to select/permutate its bits.
	 * @param table - a hard-coded table or list specifying which bits should be
	 *              selected from the input word.
	 * <p>
	 * @return the selected bits from the input word. The LSB is at the leftmost
	 *         position.
	 */
	private static long permutate(long v, byte[] table) {
		long result = 0;
		for (int i = 0; i < table.length; i++) {
			result |= ((v >>> (64 - table[i])) & 1) << (table.length - (i + 1));
		}
		return result << (64 - table.length);
	}

	/**
	 * Utility method for getting the low bits from a word of n-bits
	 * <p>
	 * @param nBits - the number of bits in the word
	 * @param word  - a word of bits
	 * <p>
	 * @return - the low bits part of the given word
	 */
	private static int getLowerBits(int nBits, long word) {
		long mask = 0x80000000_00000000L;
		mask >>= nBits - 1;
		mask &= word;
		mask >>>= (64 - nBits);
		return (int) (mask << (32 - nBits));
	}

	/**
	 * Utility method for getting the high bits from a word of n-bits
	 * <p>
	 * @param nBits - the number of bits in the word
	 * @param word  - a word of bits
	 * <p>
	 * @return - the high bits part of the given word
	 */
	private static int getHigherBits(int nBits, long word) {
		long tmp = word << nBits;
		return getLowerBits(nBits, tmp);
	}

	/**
	 * Rotates left a 28bit word.
	 * <p>
	 * @param val      - the 28bits word.
	 * @param distance - the number of positions to rotate.
	 * <p>
	 * @return - a 28bit word.
	 */
	private static int leftRotate(int val, int distance) {
		int result = Integer.rotateLeft(val, distance);
		int mask = (distance == 1) ? 0x0000_0001 : 0x0000_0003;
		int bits = (result & mask) << 4;
		result |= bits;
		result >>>= 4;
		return result << 4;
	}

	/**
	 * Performs concatenation of the two C and D parts of each sub-key.
	 * <p>
	 * @param c_i
	 * @param d_i <p>
	 * @return a 'long' containing a 48bit key. The LSB is at the leftmost
	 *         position.
	 */
	private static long concatenate(int c_i, int d_i) {
		long trimmedC = c_i >>> 4;
		long trimmedD = d_i >>> 4;
		long result = trimmedC;
		result <<= 28;
		result |= trimmedD;
		return result << 8;
	}

	/**
	 * Generates the 16 sub-keys. Each key is a 48bit long word.
	 * <p>
	 * @param c_0 - the lowest 28 bits corresponding to the original key.
	 * @param d_0 - the highest 28 bits corresponding to the original key.
	 */
	private static void generateKeys(int c_0, int d_0) {
		subKeys = new long[16];
		int c_next, c_prev = c_0;
		int d_next, d_prev = d_0;
		for (int i = 1; i <= subKeys.length; i++) {
			int v = (i == 1 || i == 2 || i == 9 || i == 16) ? 1 : 2;
			c_next = leftRotate(c_prev, v); //debug28BitsWord(c_next, i, "C", 2);
			d_next = leftRotate(d_prev, v); //debug28BitsWord(d_next, i, "D", 2);
			long k_i = concatenate(c_next, d_next);
			subKeys[i - 1] = permutate(k_i, PC2);
			c_prev = c_next;
			d_prev = d_next;
		}
	}

	/**
	 * Prints the 16 sub-keys.
	 */
	private static void debugKeys() {
		System.out.println("Sub Keys List:");
		int i = 0;
		for (long k : subKeys) {
			debug48BitsWord(k, ++i, "K", 2);
		}
	}

	/**
	 * Prints the contents of a 28bit word.
	 * <p>
	 * @param bitsWord - a 28bit word such that its LSB is at the leftmost
	 *                 position.
	 * @param idx      - an index (For reference only).
	 * @param name     - a name (For reference only).
	 * @param radix    - can be either 2 for binary or 16 for hexadecimal.
	 */
	private static void debug28BitsWord(int bitsWord, int idx, String name, int radix) {
		if (radix == 2) {
			String binaryString = Integer.toBinaryString(bitsWord);
			StringBuilder sb = new StringBuilder(binaryString);
			for (int i = 0; i < Integer.numberOfLeadingZeros(bitsWord); i++) {
				sb.insert(i, 0);
			}
			sb.delete(28, 32);
			binaryString = sb.toString();
			System.out.printf("%s%d = %s\n", name, idx, binaryString);
		} else {
			System.out.printf("%s%d = 0x%08x\n", name, idx, bitsWord);
		}

	}

	/**
	 * Prints the contents of a 48bit word.
	 * <p>
	 * @param bitsWord - a 48bit word such that its LSB is at the leftmost
	 *                 position.
	 * @param idx      - an index (For reference only).
	 * @param name     - a name (For reference only).
	 * @param radix    - can be either 2 for binary or 16 for hexadecimal.
	 */
	private static void debug48BitsWord(long bitsWord, int idx, String name, int radix) {
		if (radix == 2) {
			String binaryString = Long.toBinaryString(bitsWord);
			StringBuilder sb = new StringBuilder(binaryString);
			for (int i = 0; i < Long.numberOfLeadingZeros(bitsWord); i++) {
				sb.insert(i, 0);
			}
			sb.delete(48, 64);
			binaryString = sb.toString();
			System.out.printf("%s%d = %s\n", name, idx, binaryString);
		} else {
			System.out.printf("%s%d = 0x%016x\n", name, idx, bitsWord);
		}
	}

	/**
	 * Reads the key used to encode/decode the message from the specified file.
	 * <p>
	 * @param kFile - The file containing the key. The key must be an
	 *              hexadecimal word of length 16.
	 * <p>
	 * @return a 'long' containing the bits of the key.
	 * <p>
	 * @throws FileNotFoundException - If the file could not be found.
	 */
	private static long readKey(File kFile) throws FileNotFoundException {
		long key = 0;
		keyFile = new RandomAccessFile(kFile, "r");
		try {
			key = Long.parseLong(keyFile.readLine(), 16);
		} catch (NumberFormatException ex) {
			System.err.println(
				"Invalid key format!\n"
				+ " Check the file containing the key");
		} catch (IOException ex) {
			System.err.println("I/O Error: Failed to read the file");
		}
		return key;
	}

	/**
	 * Reads a 64-bit block (8 bytes) from the file containing the message.
	 * <p>
	 * @param pFile the file containing the message.
	 * <p>
	 * @return the total number of bytes read into the buffer, or -1 if there is
	 *         no more data because the end of this file has been reached.
	 * <p>
	 * @throws FileNotFoundException - if the file couldn't be found.
	 */
	private static int readBlock(File pFile) throws FileNotFoundException {

		// Check initialization
		if (plaintextFile == null) {
			plaintextFile = new RandomAccessFile(pFile, "r");
		}

		byte[] buffer = new byte[8];
		int bytesRead = 0;
		try {
			bytesRead = plaintextFile.read(buffer);
			block = parse64BitWord(buffer);
		} catch (IOException ex) {
			System.err.println("I/O Error: Failed to fetch next block!");
		}
		return bytesRead;
	}

	/**
	 * Performs the 'f' function part in the DES Algorithm.\n See spec. for more
	 * details.
	 * <p>
	 * @param r_prev - a 32bit word.
	 * @param key    - a 48bit word, containing the current key.
	 * <p>
	 * @return - a 32bit word such that,\n R_i = E(R_i-1) XOR K_i.
	 */
	private static int f(int r_prev, long key) {
		// Expand R_i−1 = r1,r2,...,r32 from 32 to 48 bits using E.
		long t = expand(r_prev);
		// T' = T xor Ki
		t ^= key;

		/*
		 * Represent T as eight words (Bi) of 6-bit characters each: T' = (B1,
		 * B2, ..., B8).
		 */
		byte[] B = new byte[8];
		for (int i = 0; i < 8; i++) {
			long mask = 0xFC000000_00000000L >>> 6 * i;
			mask &= t;
			mask = Long.rotateLeft(mask, 6 * (i + 1));
			B[i] = (byte) mask;
		}

		/*
		 * T'' = (S1(B1),S2(B2),...,S8(B8)) (Here Si(Bi) maps Bi = b1b2...b6 to
		 * the 4-bit entry in row r and column c of Si, where: r = 2 * b1 + b6,
		 * and b2,b3,b4,b5 is the radix-2 representation of 0 <= c <= 15. Thus
		 * S1(011011) yields r=1, c=13, and output 5 = 0101.)
		 */
		int j;
		byte[] SB = new byte[8];
		for (int i = 0; i < 8; i++) {
			byte lsb = (byte) (B[i] & 0x1);
			byte msb = (byte) ((B[i] & 0x20) >>> 5);
			byte mid = (byte) ((B[i] & 0x1E) >>> 1);
			j = (msb << 1) | lsb;

			SB[i] = S_BOX[i][j][mid];
		}

		/*
		 * T''' = P(T''). (Use P to permute the 32 bits of T'' = t1,t2,...,t32
		 * yielding t16,t7,...,t25.)
		 */
		int result = 0;
		for (int i = 0; i < 8; i++) {
			result <<= 4;
			result |= SB[i]; // SB[i] uses only 4 bits out of 8 - No sign ext.
		}
		result = (int) (permutate((long) result << 32, P) >>> 32);
		return result;
	}

	/**
	 * Exchanges between the 32 lowest bits and the 32 highest bits.
	 * <p>
	 * @param l - the 32 lowest bits
	 * @param r - the 32 highest bits
	 * <p>
	 * @return a 'long' where the first (from left to right) 32 bits correspond
	 *         to 'r' and the last 32 bits correspond to 'l'.
	 */
	private static long exchange(int l, int r) {
		long result = (((long) r) << 32) >>> 32;
		result <<= 32;
		result |= (((long) l) << 32) >>> 32;
		return result;
	}

	/**
	 * Expands from 32bit to 48bit word as per E table.
	 * <p>
	 * @param r_prev - the 32bit word.
	 * <p>
	 * @return a 'long' where its leftmost bit is the LSB in the 48bit word.
	 */
	private static long expand(int r_prev) {
		long result = 0;
		boolean currBit;
		for (int i = 0; i < E_BOX.length; i++) {
			result <<= 1;
			currBit = getBit(E_BOX[i], r_prev);
			result |= currBit ? 1 : 0;
		}
		return result << 16;
	}

	/**
	 * Utility method that facilitates access to the n-th bit of a given word.
	 * <p>
	 * @param n - a value in the mathematical range: [1,32];
	 * @param w - a 32bit word (an 'int').
	 * <p>
	 * @return TRUE if the n-th bit from the given word is 1 or FALSE otherwise;
	 */
	private static boolean getBit(byte n, int w) {
		if (n > Integer.SIZE || n < 0) {
			String msg = "First argument is out of range!\n"
				+ "Valid range is: 1 <= n <= 32";
			throw new IllegalArgumentException(msg);
		}
		return ((w >>> (32 - n)) & 1) == 1;
	}

	/**
	 * Utility method that facilitates access to the n-th bit of a given word.
	 * <p>
	 * @param n - a value in the mathematical range: [1,64];
	 * @param w - a 64bit word (an 'long').
	 * <p>
	 * @return TRUE if the n-th bit from the given word is 1 or FALSE otherwise;
	 */
	private static boolean getBit(byte n, long w) {
		if (n > Long.SIZE || n < 0) {
			String msg = "First argument is out of range!\n"
				+ "Valid range is: 1 <= n <= 64";
			throw new IllegalArgumentException(msg);
		}
		return ((w >>> (64 - n)) & 1) == 1;
	}

	/**
	 * Converts the contents of the given buffer into a 64bit word, such that
	 * the LSB is at the leftmost position.
	 * <p>
	 * @param buffer a buffer containing 8 bytes.
	 * <p>
	 * @return a 'long' representing the bytes in the given buffer.
	 */
	private static long parse64BitWord(byte[] buffer) {
		int d = (64 - buffer.length);
		long result = 0;
		for (int i = 0; i < buffer.length; i++) {
			result <<= buffer.length;
			long currByte = (((long) buffer[i] << d) >>> d);
			result |= currByte;
		}
		return result;
	}

	private static void writeBlock(File outFile, long result) throws FileNotFoundException {
		if (outputFile == null) {
			outputFile = new RandomAccessFile(outFile, "rw");
		}
		try {
			outputFile.writeLong(result);
		} catch (IOException ex) {
			System.err.println("I/O Error: Couldn't write current block.");
		}
	}

}
