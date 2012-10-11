package com.officialsounding.crypto.util;

import com.officialsounding.crypto.base.*;

public class CryptoDefinition {

	private final CipherBase cb;
	private final OperatingModeBase omb;
	
	public CryptoDefinition(CipherBase instance, OperatingModeBase omb) {
		this.cb = instance;
		this.omb = omb;
	}

	public CipherBase getCb() {
		return cb;
	}

	public OperatingModeBase getOmb() {
		return omb;
	}
	
	
}
