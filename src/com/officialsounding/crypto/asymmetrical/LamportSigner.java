package com.officialsounding.crypto.asymmetrical;

import java.security.InvalidKeyException;
import java.util.Arrays;

import com.officialsounding.crypto.base.*;
import com.officialsounding.crypto.hash.SHA256;
import com.officialsounding.crypto.keys.LamportPrivateKey;
import com.officialsounding.crypto.keys.LamportPublicKey;

public class LamportSigner implements SigningBase {

	public boolean verify(PublicKey pubk, byte[] message, SignatureContainer signature) {
		if(pubk instanceof LamportPublicKey && signature instanceof LamportSignature){
			SHA256 sha = new SHA256();
			byte[] hash = sha.digest(message);
			byte[][] sigbytes = ((LamportSignature) signature).getSignature();
			byte[][][] pubkeybytes = ((LamportPublicKey) pubk).getKeyBytes();
			int i = 0;
			for(byte b: hash){
				for(int n = 0; n < 8; n++){
					if(!Arrays.equals(sigbytes[i], pubkeybytes[i][(b & 0x1)])){
						return false;
					}
					b >>= 1;
				}
			}
			
			return true;
		}else{
			return false;
		}
	}

	public SignatureContainer sign(PrivateKey privk, byte[] message) throws InvalidKeyException{
		// TODO Auto-generated method stub
		if(privk instanceof LamportPrivateKey){
		SHA256 sha = new SHA256();
		byte[] hash = sha.digest(message);
		byte[][] signature = new byte[256][32];
		
		int i = 0;
		for(byte b: hash){
			for(int n = 0; n < 8; n++){
				signature[i] = ((LamportPrivateKey)privk).getKeyBytes()[i][(b & 0x1)];
				b >>= 1;
			}
		}
		
		return new LamportSignature(signature);
		}else{
			throw new InvalidKeyException("private key is not an instance of LamportPrivateKey");
		}
	}

	public KeyPair<LamportPublicKey,LamportPrivateKey> getKeyPair(){
		LamportPrivateKey privatekey = new LamportPrivateKey();
		LamportPublicKey publickey = new LamportPublicKey(privatekey);
		
		return new KeyPair<LamportPublicKey,LamportPrivateKey>(publickey,privatekey);
	}
}
