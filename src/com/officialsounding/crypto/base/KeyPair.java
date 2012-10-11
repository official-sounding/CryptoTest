package com.officialsounding.crypto.base;

import java.io.Serializable;

public class KeyPair<P extends PublicKey,R extends PrivateKey> implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 4761378224397900720L;
	
	private final P pubk;
	private final R privk;
	
	public KeyPair(P pubk, R privk) {
		this.pubk = pubk;
		this.privk = privk;
	}
	
	public P getPublicKey(){
		return pubk;
	}
	
	public R getPrivateKey(){
		return privk;
	}
}
