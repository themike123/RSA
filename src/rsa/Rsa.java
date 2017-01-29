/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rsa;

//Librerias a importar
import java.math.BigInteger;
import java.util.*;
import java.io.*;
import java.security.SecureRandom;

/**
 *
 * @author miguel
 */

public class Rsa {
    
    //Variables
    private final static SecureRandom random = new SecureRandom();
    private int num_bits;
    private BigInteger n,p,q;
    private BigInteger phi;
    private BigInteger e, d;
    
    /**
     * Constructores
     */ 
    public Rsa(int num_bits)
    {
        this.num_bits=num_bits;
        this.GeneratePrimos();
        this.GenerateKeys();
    }
    
    public Rsa(int num_bits,BigInteger p, BigInteger q)
    {
        this.num_bits=num_bits;
        this.p=p;
        this.q=q;
        this.GenerateKeys();
    }
    
    /**
     * Gerenera a p y q
     */ 
    public void GeneratePrimos()
    {   
        p = BigInteger.probablePrime(this.num_bits, random);
        do{    
            q =BigInteger.probablePrime(this.num_bits, random);
        }while(q.compareTo(p)==0);
    }
    
    /**
     * Gerenera a n,e y d
     */ 
    public void GenerateKeys()
    {
        n = p.multiply(q);
        // phi = (p-1)*(q-1)
        phi = p.subtract(BigInteger.valueOf(1));
        phi = phi.multiply(q.subtract(BigInteger.valueOf(1)));
        //e = new BigInteger("65537");//valor por defaul
        do{ 
            e = BigInteger.probablePrime(this.num_bits, random);
        }while( !( (e.compareTo(phi) == -1) && (e.compareTo(BigInteger.valueOf(1)) == 1) || (e.gcd(phi).compareTo(BigInteger.valueOf(1)) == 0) ) );
        d = e.modInverse(phi);
    }
    
    /**
     * Encripta el texto usando la clave pública
     *
     * @param   mensaje     Mensaje a encriptar
     * @return   El mensaje cifrado como un vector de BigIntegers
     */
    public BigInteger[] encripta(String mensaje)
    {
        byte[] temp = new byte[1];
        //Transforma el mensaje en una secuencia de bits
        byte[] digitos = mensaje.getBytes();
        BigInteger[] bigdigitos = new BigInteger[digitos.length];
        BigInteger[] encriptado = new BigInteger[bigdigitos.length];
        
        for(int i=0; i<bigdigitos.length;i++){
            temp[0] = digitos[i];
            bigdigitos[i] = new BigInteger(temp);
        }
        
        for(int i=0; i<bigdigitos.length; i++)
            encriptado[i] = bigdigitos[i].modPow(e,n);
        
        return(encriptado);
    }
    
    /**
     * Desencripta el texto cifrado usando la clave privada
     *
     * @param   mensaje cifrado       
     * @return  El mensaje descifrado
     */
    public String desencripta(BigInteger[] encriptado) 
    {
        BigInteger[] desencriptado = new BigInteger[encriptado.length];
        char[] charArray = new char[desencriptado.length];   
        
        for(int i=0; i<desencriptado.length; i++){
            desencriptado[i] = encriptado[i].modPow(d,n);
        }
        
        for(int i=0; i<charArray.length; i++){
            charArray[i] = (char) (desencriptado[i].intValue());
        }
            
        return(new String(charArray));
    }
    
    //Getter y Setter de los atributos 
    public BigInteger getN(){ return n;}
    public void setN(BigInteger n){ this.n = n;}

    public BigInteger getP(){ return p;}
    public void setP(BigInteger p){ this.p = p;}

    public BigInteger getQ(){ return q;}
    public void setQ(BigInteger q){ this.q = q;}

    public BigInteger getPhi(){ return phi;}
    public void setPhi(BigInteger phi){ this.phi = phi;}
    
    public BigInteger getE(){ return e;}
    public void setE(BigInteger e){ this.e = e;}
    
    public BigInteger getD(){ return d;}
    public void setD(BigInteger d){ this.d = d;}       
    
}
