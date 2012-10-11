package com.officialsounding.crypto.cipher;

import java.security.*;
import java.util.*;

import com.officialsounding.crypto.util.Card;
import com.officialsounding.crypto.util.Card.Rank;
import com.officialsounding.crypto.util.Card.Suit;

public class Mirdek {

	protected String iv;
	protected boolean initialized;
	//the piles used for the algorithm
	protected LinkedList<Card> r,l,d,a1,a2;

	/**
	 * Encrypt applies the Mirdek algorithm to a string of text
	 * @param pt the plaintext to encrypt.  Any characters that aren't letters are ignored
	 * @return a string of uppercase characters organized into groups of 5.  Initialization Vector appended to the front
	 * @throws IllegalStateException if the cipher has not be initialized
	 */
	public String encrypt(String pt) throws IllegalStateException{
		//throw an exception if the cipher state has not been initialized
		if(!initialized)
			throw new IllegalStateException("Cipher not initialized");

		int ci;
		char[] ptarr = pt.toCharArray();
		List<Character> ctarr = new ArrayList<Character>();
		int i = 0;
		int n = 0;
		
		for(char p: ptarr){
			try{
				//convert character to a card object first to trip an exception
				Card pc = charToCard(p,false);
				//do a counted Cut
				countedCut();
				//do a letter search based on the current plaintext character
				ci = letterSearch(pc);
				//convert the number of cards counted to a character, store it as next ciphertext character
				ctarr.add(alphaPositionToChar(ci));
				i++;
				n++;
				//insert a whitespace character every 5 ciphertext character
				if(i%5 == 0 && i < ptarr.length-1 && i != 0){
					ctarr.add(Character.valueOf(' '));
				}
			}catch(IllegalArgumentException e){

			}
		}
		//pad ciphertext out to a multiple of 5 using "X" as a plaintext
		if(n%5 != 0){
			for(i = 0; i < (5- (n % 5)); i++){
				countedCut();
				ci = letterSearch('x',false);
				ctarr.add(alphaPositionToChar(ci));
			}
		}

		//convert List<Character> to a String
		Character[] ct1 = ctarr.toArray(new Character[0]);
		char[] ct2 = new char[ct1.length];
		i = 0;

		for(Character ch: ct1){
			ct2[i] = ch;
			i++;
		}

		String ct = new String(ct2);
		//return iv + ciphertext
		return iv +" "+ct;
	}

	public String decrypt(String ct, boolean hasIV) throws IllegalStateException{
		if(!initialized)
			throw new IllegalStateException("Cipher not initialized");

		char[] ctarr;
		int i = 0;
		List<Character> ptarr = new ArrayList<Character>();


		//strip IV if present
		//IV is first 25 characters and 5 spaces
		if(hasIV){
			ctarr = ct.substring(30).toCharArray();
		}else{
			ctarr = ct.toCharArray();
		}

		for(char c: ctarr){
			if(Character.isLetter(c)){
				countedCut();
				ptarr.add(inverseLetterSearch(c));
				i++;
				if(i%5 == 0 && i < ctarr.length-1 && i != 0){
					ptarr.add(Character.valueOf(' '));
				}
			}
		}

		Character[] pt1 = ptarr.toArray(new Character[0]);
		char[] pt2 = new char[pt1.length];
		i = 0;

		for(Character ch: pt1){
			pt2[i] = ch;
			i++;
		}
		return  new String(pt2);
	}
	/**
	 * Initialize the cipher state, generating a new Initialization Vector
	 * @param key the key to be used for the cipher
	 * @return the Initialization Vector
	 * @throws InvalidKeyException if there are illegal characters in the key
	 */
	public String initialize(String key) throws InvalidKeyException {
		initalizeDeck(false,new String());
		keyDeck(key);
		mixDeck();
		initialized = true;
		
		return iv;
	}

	/**
	 * Initialize the cipher state, using an existing Initialization Vector
	 * @param key the key to be used for the cipher
	 * @param IV the initialization vector to be used for the cipher
	 * @throws InvalidKeyException if there are illegal characters in the key or IV
	 */
	public void initialize(String key, String IV) throws InvalidKeyException {
		initalizeDeck(true,IV);
		keyDeck(key);
		mixDeck();
		initialized = true;
	}

	/**
	 * this is step one of the initialization process: it sets up the initial piles
	 * then either applies the existing initialization vector or generates a new one
	 * @param hasIV indicates whether to generate a new IV or use the supplied one
	 * @param IV only used if hasIV is true
	 * @throws InvalidKeyException if the IV has illegal characters
	 */
	protected void initalizeDeck(boolean hasIV, String IV) throws InvalidKeyException{
		r = new LinkedList<Card>();
		l = new LinkedList<Card>();
		d = new LinkedList<Card>();
		a1 = new LinkedList<Card>();
		a2 = new LinkedList<Card>();

		LinkedList<Card> temp = new LinkedList<Card>();
		char[] ivarr;
		//build decks
		//left deck is clubs and then hearts
		for(Rank rank: Rank.values()){
			if(rank != Rank.A && rank != Rank.B)
				l.add(new Card(rank,Card.Suit.CLUBS));
		}
		for(Rank rank: Rank.values()){
			if(rank != Rank.A && rank != Rank.B)
				l.add(new Card(rank,Card.Suit.HEARTS));
		}

		//temporary right deck is spades and then diamonds
		for(Rank rank: Rank.values()){
			if(rank != Rank.A && rank != Rank.B)
				temp.add(new Card(rank,Card.Suit.SPADES));
		}
		for(Rank rank: Rank.values()){
			if(rank != Rank.A && rank != Rank.B)
				temp.add(new Card(rank,Card.Suit.DIAMONDS));
		}
		//if IV is supplied
		if(hasIV){
			//sort right deck in order of IV
			ivarr = IV.toCharArray();
			for(char i: ivarr){
				try{
					Card c = charToCard(i,true);
					r.push(c);
					temp.remove(c);
				}catch(IllegalArgumentException e){
					if(!Character.isWhitespace(i)){
						throw new InvalidKeyException("IV contains an invalid character: "+e.getMessage());
					}
				}
			}
			//push the final value onto the right deck
			r.push(temp.pop());
		}else{
			//otherwise, shuffle right deck
			SecureRandom rnd = new SecureRandom();
			Collections.shuffle(temp,rnd);
			//holding right deck face-up get ordering of right deck as IV, placing the cards face-down
			ivarr = new char[29];
			for(int i = 0, n = 1; i < 29; i++,n++){
				Card c = temp.pop();
				ivarr[i] = cardToChar(c);
				r.push(c);
				if(n % 5 == 0 && n != 0 && n != 25){
					i++;
					ivarr[i] = ' ';
				}

			}
			//get last card from temporary deck
			r.push(temp.pop());
		}
		//record IV for first 25 characters of ciphertext
		iv = new String(ivarr);
	}

	/**
	 * This is step 2 of the initialization process.
	 * @param key the key supplied for the cipher
	 * @throws InvalidKeyException thrown if illegal characters are found in the key
	 */
	protected void keyDeck(String key) throws InvalidKeyException{
		char[] karr = key.toCharArray();
		for(char k: karr){
			try{
				countedCut();
				letterSearch(k,false);
			}catch(IllegalArgumentException e){
				if(!Character.isWhitespace(k))
					throw new InvalidKeyException("Key contains an invalid character: "+e.getMessage());
			}
		}

	}

	/**
	 * The third and final step of the initialization process.  
	 * This phase thoroughly mixes the state of the deck before encryption starts
	 */
	protected void mixDeck(){
		LinkedList<Card> temp = new LinkedList<Card>();
		//flip over the r deck
		moveDeck(r,temp,true);
		//put the face-up right deck underneath the discard deck
		d.addAll(temp);
		//place the left deck face-down as the new right deck
		moveDeck(l,r,true);
		//pick up the face-up discard deck as the new face-up left deck
		moveDeck(d,l,false);
		int rs = r.size();
		//for each card in the right deck
		for(int i = 0; i < rs; i++){
			//perform a letter search for that card's value
			Card c = r.pop();
			d.push(c);
			letterSearch(cardToChar(c),true);
		}

		// place the face-up left deck face-down as new right deck
		moveDeck(l,r,true);
		// pick up the face-up discard deck as the new face-up left deck
		moveDeck(d,l,false);
	}

	/**
	 * Move a deck of cards from one position to another, potentially reversing the order
	 * @param src the pile to move the deck from
	 * @param dst the pile to move the deck to
	 * @param reverse whether to reverse the order while moving the deck
	 * @return the original destination list, in case it must be used
	 */
	protected LinkedList<Card> moveDeck(LinkedList<Card> src, LinkedList<Card> dst, boolean reverse){
		//save original destination list
		LinkedList<Card> saved = new LinkedList<Card>(dst);
		dst.removeAll(dst);
		//place each card from the source pile into the destination pile, in opposite order
		int size = src.size();
		for(int i = 0; i < size; i++){
			if(reverse)
				dst.push(src.pop());
			else
				dst.add(src.pop());
		}
		return saved;
	}

	/**
	 * one of the core operations in the Mirdek Cipher.  
	 * This operation moves a set of cards from the top of the (face-up) left pile to the bottom of the left pile
	 * based on the value of the top of the (face-down) right pile
	 * if this operation exhasts the right pile, the discard pile is flipped over, becomes the new right pile
	 * and another countedCut is performed
	 */
	protected void countedCut(){
		//take top card from the right stack and discard
		Card top = r.pop();
		d.push(top);

		//take the numerical value of this card
		//place that many cards from the top of the left stack on the bottom of the left stack
		int num = cardToNumber(top);
		for(int i = 0; i < num; i++){
			Card x = l.pop();
			l.add(x);
		}

		//if this action empties the right pile
		if(r.isEmpty()){
			//place the face-up left deck face-down as new right deck
			moveDeck(l,r, true);
			//place face-up discard deck face-up as new left deck
			moveDeck(d,l, false);
			//perform another counted cut
			countedCut();
		}
	}


	/**
	 * This is a wrapper for letterSearch to search for a letter based on charcter value
	 * @param c the character to search for
	 * @param swapped if the left and right piles have been swapped from their "normal" locations (e.g. during mixDeck()), set this to true
	 * @return the number of cards searched before finding c.
	 */
	protected int letterSearch(char c,boolean swapped){
		return letterSearch(charToCard(c,swapped));
	}

	/**
	 * The other core operation of the Mirdek cipher.  puts cards from the left pile into two alternating piles (a1 and a2) until the supplied card is found
	 * then the a1 and a2 decks are combined and placed under the left deck
	 * @param needle
	 * @return
	 */
	protected int letterSearch(Card needle){
		int count = 0;
		LinkedList<Card> a = new LinkedList<Card>();
		Card c = Card.cardByDeckPosition(0);
		do{
			count++;
			c = l.pop();
			if(count % 2 == 1){
				a1.push(c);
			}else{
				a2.push(c);
			}

		}while(!c.equals(needle));
		//when the card is found
		//place the pile containing the found card on top of the other pile
		if(count % 2 == 1){
			moveDeck(a1,a,false);
			a.addAll(a2);
			a2.removeAll(a2);
		}else{
			moveDeck(a2,a,false);
			a.addAll(a1);
			a1.removeAll(a1);
		}
		//place combined pile underneath the left deck
		l.addAll(a);
		//return number of cards searched to find the named card
		return count;
	}
	/**
	 * the Inverse Letter Search is used during decryption
	 * a certain number of cards (equal to the alphabet position of needle) are dealt out, and then the last card dealt is returned
	 * @param needle the character of the ciphertext indicating the number of cards to deal
	 * @return the character of the card last dealt
	 */
	protected char inverseLetterSearch(char needle){
		int count = charToAlphaPosition(needle);
		LinkedList<Card> a = new LinkedList<Card>();
		Card c = Card.cardByDeckPosition(0);
		while(count --> 0){
			c = l.pop();
			if(count % 2 == 1){
				a1.push(c);
			}else{
				a2.push(c);
			}
		}

		if(count % 2 == 1){
			moveDeck(a1,a,false);
			a.addAll(a2);
			a2.removeAll(a2);
		}else{
			moveDeck(a2,a,false);
			a.addAll(a1);
			a1.removeAll(a1);
		}

		//place combined pile underneath the left deck
		l.addAll(a);
		//return number of cards searched to find the named card
		return cardToChar(c);
	}
	
	/**
	 * helper function to convert between the bridge values of the card and the mirdek values of the card
	 * @param c
	 * @return
	 */
	protected int cardToNumber(Card c){
		int n;
		n = c.getCardValue();

		//slight modification between bridge ordering (for Solitaire)
		//and ordering for Mirdek
		if(c.suit() == Card.Suit.SPADES){
			n-=39;
		}else if(c.suit() == Card.Suit.HEARTS){
			n-=13;
		}
		return n;
	}

	/**
	 * convert from a Card object to its equivalent character value
	 * @param c
	 * @return
	 */
	protected char cardToChar(Card c){
		int n = cardToNumber(c);
		return alphaPositionToChar(n);
	}

	/**
	 * convert from a character to a Card object, either from the left or right side
	 * @param c the card to Convert
	 * @param rightside whether the card is in the right or left pile
	 * @return a Card object
	 * @throws IllegalArgumentException if the character is not a letter
	 */
	protected Card charToCard(char c, boolean rightside) throws IllegalArgumentException{
		int n = charToAlphaPosition(c);
		Rank rank;
		Suit suit;

		if(n <= 13){
			suit = rightside ? Suit.SPADES : Suit.CLUBS;
		}else{
			suit = rightside ? Suit.DIAMONDS : Suit.HEARTS;
			n-=13;
		}
		rank = Card.getRankByNumber(n);
		return new Card(rank,suit);
	}

	/**
	 * convert an uppercase or lowercase letter to it's position in the alphabet
	 * @param x the character to be converted
	 * @return a number between 1 and 26
	 * @throws IllegalArgumentException if the character is not a letter
	 */
	protected int charToAlphaPosition(char x) throws IllegalArgumentException {

		if(!Character.isUpperCase(x) && !Character.isLowerCase(x)){
			throw new IllegalArgumentException("'"+x+"' is not a character in the alphabet");
		}
		//Character.getNumericValue outputs a number between 10 and 35
		//regardless if the letter is upper or lower case
		int n = Character.getNumericValue(x);
		n-=9;

		return n;
	}

	/**
	 * convert from a position in the alphabet to a character
	 * @param i
	 * @return
	 */
	protected char alphaPositionToChar(int i){
		return (char)(i+64);
	}

	/**
	 * for debug purposes, output the current contents and sizes of all of the piles used in the algorithm
	 */
	protected void debugPiles(){
		System.err.println("==== Pile States ====");
		System.err.print("Left Pile: ");
		debugPile(l);
		System.err.print("Right Pile: ");
		debugPile(r);
		System.err.print("Discard Pile: ");
		debugPile(d);
		System.err.print("A Pile 1: ");
		debugPile(a1);
		System.err.print("A Pile 2: ");
		debugPile(a2);		
		System.err.println("==== End Debug Output ====");
	}

	/**
	 * output the contents of a particular pile and its size
	 * @param pile
	 */
	protected void debugPile(LinkedList<Card> pile){
		System.err.print("Size: "+pile.size()+" ");
		for(Card c: pile){
			System.err.print(cardToChar(c));
		}
		System.err.println();
	}
}
