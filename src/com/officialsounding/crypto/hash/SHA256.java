package com.officialsounding.crypto.hash;

import java.util.Arrays;

import com.officialsounding.crypto.util.Util;

public class SHA256 {
	
	
	private final int[] h_init = { 
			0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
			0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	
	private final int[] k = { 
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
			0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
			0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
			0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
			0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
			0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
	
	private final int BLOCKSIZE = 64;
	private final int ROUNDCOUNT = 64;
	private final int OUTPUTSIZE = 32;
	
	/**
	 * Pre-process and pad input
	 * @param input the byte aUtil.rray representing the hash input
	 * @return the input + padding byte aUtil.rray
	 */
	private byte[] preProcess(byte[] input){
		//add a extra block to the end of the input, less the length mod block size
		int size = input.length + (BLOCKSIZE - (input.length % BLOCKSIZE));
		byte[] result = Arrays.copyOf(input,size);
		
		//padding begins with a 1 and a set of zeros
		result[input.length] = (byte) 0x80;
		
		//end of padding is the length of the input
		//convert the size of the message in bytes to the size in bits
		long bits = input.length << 3;
		int padto = size - 8;
		result[padto++] = (byte) (bits >>> 56);
		result[padto++] = (byte) (bits >>> 48);
		result[padto++] = (byte) (bits >>> 40);
		result[padto++] = (byte) (bits >>> 32);
		result[padto++] = (byte) (bits >>> 24);
		result[padto++] = (byte) (bits >>> 16);
		result[padto++] = (byte) (bits >>> 8);
		result[padto++] = (byte) bits;
		
		return result;
	}

	/**
	 * digest an input into a SHA 256 output
	 * @param input a byte aUtil.rray of the input
	 * @return a byte aUtil.rray representing the SHA-256 output
	 */
	public byte[] digest(byte[] input){
		int[] h,w,state;
		byte[] output = new byte[OUTPUTSIZE];
		
		
		h = Arrays.copyOf(h_init, h_init.length);
		
		input = preProcess(input);
		
		for(int c = 0; c < input.length; c+=BLOCKSIZE){
			
			//expand chunk into sixty-four 32-bit words
			w = createW(input,c);
			
			//initialize state values for this chunk
			state = Arrays.copyOf(h, h.length);
			
			//perform the main loop
			for(int i = 0; i < ROUNDCOUNT; i++){
				shaRound(state, w[i], k[i]);
			}
			
			//after main loop, add values to hash state
			for(int i = 0; i < h.length; i++){
				h[i]+=state[i];
			}
		}
		
		//turn hash state back into bytes
		int n = 0;
		for(int i = 0; i < h.length; i++){
			output[n++] = (byte) (h[i] >>> 24);
			output[n++] = (byte) (h[i] >>> 16);
			output[n++] = (byte) (h[i] >>> 8);
			output[n++] = (byte) h[i];
		}
		return output;
	}
	
	public int getOutputSize(){
		return OUTPUTSIZE;
	}
	
	/**
	 * take a block of input, and expand it into the W aUtil.rray for the main round function
	 * @param input the byte aUtil.rray representing the input to be hashes
	 * @param offset the offset to start from within the byte aUtil.rray
	 * @return
	 */
	private int[] createW(byte[] input, int offset){
		int[] w = new int[ROUNDCOUNT];
		int t,t2,s0,s1;
		//first 16 values are the first 64 bytes of the input
		for(int i = 0; i < 16; i++){
			for(int j = 0; j < 4; j++){
				w[i] <<= 8;
				w[i] |= (input[offset++] & 0xFF);
			}
		}
		
		//the rest of the values are populated in this loop
		for(int i = 16; i < w.length; i++){
			t = w[i-2];
			t2 = w[i-15];
			
			s0 = Util.rr(t,17) ^ Util.rr(t,19) ^ (t >>> 10);
			s1 = Util.rr(t2,7) ^ Util.rr(t2,18) ^ (t2 >>> 3);
			
			w[i] = w[i-16] + s0 + w[i-7] + s1;
		}
		
		return w;
	}
	/**
	 * The main round function of for the SHA 256 function
	 * @param state the state for the given block of input
	 * @param w the element from the w aUtil.rray used in this iteration
	 * @param k the element from the k aUtil.rray used in this iteration
	 */
	private void shaRound(int[] state,int w, int k){
		
		int a,b,c,d,e,f,g,h;
		
		//get values from state
		a = state[0];
		b = state[1];
		c = state[2];
		d = state[3];
		e = state[4];
		f = state[5];
		g = state[6];
		h = state[7];
		
		//calculate transformation values
		int t1 = h + Ch(e,f,g) + s1(e) + w + k;
		int t2 = Ma(a,b,c) + s0(a);
		
		//put new values in the state
		state[0] = t1 + t2;
		state[1] = a;
		state[2] = b;
		state[3] = c;
		state[4] = d + t1;
		state[5] = e;
		state[6] = f;
		state[7] = g;
	}
	
	private int Ch(int e, int f, int g){
		return (e & f) ^ (~e & g);
	}
	
	private int Ma(int a, int b, int c){
		return (a & b) ^ (a & c) ^ (b & c);
	}
	
	private int s0(int A){
		return Util.rr(A,2) ^ Util.rr(A,13) ^ Util.rr(A,22);
	}
	
	private int s1(int E){
		return Util.rr(E,6) ^ Util.rr(E,11) ^ Util.rr(E,25);
	}
	


}
