package com.officialsounding.crypto.util;

import java.math.BigInteger;
import java.util.Arrays;

import com.officialsounding.crypto.base.CipherBase;

public class Util {

	
	/**
	 * convert a byte array to a hex string
	 * @param bytes
	 * @return
	 */
	public static String toHex(byte[] bytes) {
	    BigInteger bi = new BigInteger(1, bytes);
	    return String.format("%0" + (bytes.length << 1) + "x", bi);
	}
	
	/**
	 * Perform a right rotate operation on an integer
	 * shift rotate bits right, moving bits rotated off of the low end to the high end
	 * @param n the integer to shift
	 * @param rotate the number of bits to shift right
	 * @return the right-rotated integer
	 */
	public static int rr(int n, int rotate){
		return ((n >>> rotate) | (n << 32-rotate));
	}
	/**
	 * Perform a right rotate operation on a byte array
	 * shift rotate bits right, moving bits rotated off of the low end to the high end
	 * @param n the byte array to shift
	 * @param rotate the number of bits to shift right, must be a multiple of 8
	 */
	public static void rr(byte[] n, int rotate) {
		byte[] original = Arrays.copyOf(n, n.length);
		if(rotate % 8 == 0){
			for(int i = 0; i < 4; i++){
				n[(i+(rotate/8))%4] = original[i];
			}
		}
	}
	
	/**
	 * Perform a left rotate operation on an integer
	 * shift rotate bits left, moving bits rotated off of the high end to the low end
	 * @param n the integer to shift
	 * @param rotate the number of bits to shift left
	 * @return the right-rotated integer
	 */
	public static int lr(int n, int rotate){
		return ((n << rotate) | (n >>> 32-rotate));
	}
	
	/**
	 * Perform a left rotate operation on a byte array
	 * shift rotate bits left, moving bits rotated off of the high end to the low end
	 * @param n the integer to shift
	 * @param rotate the number of bits to shift left, must be a multiple of 8
	 */
	public static void lr(byte[] n, int rotate) {
		byte[] original = Arrays.copyOf(n, n.length);
		if(rotate % 8 == 0){
			for(int i = 0; i < 4; i++){
				n[i] = original[(i+(rotate/8))%4];
			}
		}
		
	}
	
	/**
	 * converts an integer to a 4 element byte array
	 * @param x the integer to convert
	 * @return the byte array result
	 */
	public static byte[] intToByteArr(int x){
		byte[] ret = new byte[4];
		
		ret[0] = (byte) ((x >> 24) & 0xff);
		ret[1] = (byte) ((x >> 16) & 0xff);
		ret[2] = (byte) ((x >>  8) & 0xff);
		ret[3] = (byte) ((x      ) & 0xff);
		
		return ret;
	}
	
	public static int byteArrayToInt(byte[] x){
		int ret = 0;
		int i = 0;
		for(int j = 0; j < 4; j++){
			ret <<= 8;
			ret  |= (x[i++] & 0xff);
		}
		
		return ret;
	}
	
	/**
	 * Copy a byte array into another byte array.
	 * @param dst the destination byte array
	 * @param src the source byte array
	 * @param dstStart the index to start copying into
	 * @param srcStart the index to start copying from
	 * @param len the number of elements to copy into the destination array
	 */
	public static void copyInto(byte[] dst, byte[] src, int dstStart,  int srcStart, int len){
		for(int i = 0; i < len; i++){
			dst[i+dstStart] = src[i+srcStart];
		}
	}
	/**
	 * xors two byte arrays together.  Will xor the longer array with the shorter array
	 * leaving the remaining elements of the longer array unchanged
	 * @param a the first array to be xored
	 * @param b the second array to be xored
	 * @return
	 */
	public static byte[] xorArray(byte[] a, byte[] b){

		xorArray(a,b,0,0,a.length);
		
		return a;
	}
	
	public static void xorArray(byte[] a, byte[] b, int starta, int startb, int len){
		for(int i = 0; i < len; i++){
			a[starta+i] ^= b[startb+i];
		}
	}
	
	public static void residualBlockTerminationEncrypt(CipherBase cb, int blocksize,
			int i, byte[] ct) {
		//get last full encrypted byte
		byte[] reencryptedblk = Arrays.copyOfRange(ct,i-blocksize,i);
		
		//encrypt it again
		cb.encrypt(reencryptedblk,0);
		
		//xor it with the last plaintext block
		xorArray(ct,reencryptedblk,i,0,ct.length-i);
	}
	
	/**
	 * Concatenate two byte arrays together: a || b
	 * @param a the first array
	 * @param b the second array
	 * @return
	 */
	public static byte[] concatArray(byte[] a, byte[] b){
		byte[] newarray = new byte[a.length + b.length];
		int j = 0;
		
		for(int i = 0; i < a.length; i++,j++){
			newarray[j] = a[i];
		}
		
		for(int i = 0; i < b.length; i++,j++){
			newarray[j] = b[i];
		}
		
		return newarray;
	}
}
