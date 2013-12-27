package block_ciphers;

public class test {

	public static void main(String[] args) {

		long t = 0b0110000100010111101110101000011001100101001001110000000000000000L;
		System.out.printf("T = 0x%016x\n", t);

		byte[] B = new byte[8];
		for (int i = 0; i < 8; i++) {
			long mask = 0xFC000000_00000000L >>> 6 * i;
			mask &= t;
			System.out.printf("&Mask %d = 0x%016x", i, mask);
			mask = Long.rotateLeft(mask, 6 * (i + 1));
			B[i] = (byte) mask;
			System.out.printf(" --> B%d = 0x%x\n", i, B[i]);
		}

	}
}
