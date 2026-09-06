package android.androidVNC;
// CRYPTO LIBRARY FOR EXCHANGING KEYS
// USING THE DIFFIE-HELLMAN KEY EXCHANGE PROTOCOL

// The diffie-hellman can be used to securely exchange keys
// between parties, where a third party eavesdropper given
// the values being transmitted cannot determine the key.

// Implemented by Lee Griffiths, Jan 2004.
// This software is freeware, you may use it to your discretion,
// however by doing so you take full responsibility for any damage
// it may cause.

// Hope you find it useful, even if you just use some of the functions
// out of it like the prime number generator and the XtoYmodN function.

// It would be great if you could send me emails to: lee.griffiths@first4internet.co.uk
// with any suggestions, comments, or questions!

// Enjoy.

// Adopted to ms-logon for ultravnc and ported to Java by marscha, 2006.

import java.security.SecureRandom;
import android.util.Log;

public class DH {

        private static final String TAG = "DH";
        private static final SecureRandom secureRandom = new SecureRandom();
        
        // Minimum acceptable modulus to prevent trivial attacks
        // Set to 2^20 as a reasonable minimum for the constrained 31-bit protocol
        private static final long MIN_MODULUS = 1L << 20;
        
        // Minimum acceptable generator to prevent degenerate groups
        private static final long MIN_GENERATOR = 2;

        public DH() {
                maxNum = (((long) 1) << DH_MAX_BITS) - 1;
                Log.w(TAG, "WARNING: UltraVNC DH authentication uses a weak 31-bit key exchange protocol. " +
                                "This protocol is vulnerable to cryptographic attacks and should be avoided when possible.");
        }

        public DH(long generator, long modulus) throws Exception {
                this();
                maxNum = (((long) 1) << DH_MAX_BITS) - 1;
                
                // Validate upper bounds
                if (generator >= maxNum || modulus >= maxNum)
                        throw new Exception("Modulus or generator too large.");
                
                // Validate modulus is sufficiently large to prevent trivial attacks
                if (modulus < MIN_MODULUS)
                        throw new Exception("Modulus too small (minimum " + MIN_MODULUS + " required). Possible attack detected.");
                
                // Validate generator is not degenerate (0 or 1 would create weak/predictable keys)
                if (generator < MIN_GENERATOR)
                        throw new Exception("Generator too small (minimum " + MIN_GENERATOR + " required). Possible attack detected.");
                
                // Validate modulus is odd (even modulus would be composite and weak)
                if ((modulus & 1) == 0)
                        throw new Exception("Modulus is even (must be odd prime). Possible attack detected.");
                
                // Validate generator is less than modulus
                if (generator >= modulus)
                        throw new Exception("Generator must be less than modulus. Invalid parameters.");
                
                // Perform basic primality check on modulus using Miller-Rabin
                if (!millerRabin(modulus, 25))
                        throw new Exception("Modulus failed primality test. Possible attack detected.");
                
                gen = generator;
                mod = modulus;
        }

        private long rng(long limit) {
                // Use SecureRandom instead of Math.random() for cryptographic operations
                // Generate random bytes and convert to long in range [0, limit)
                if (limit <= 0) {
                        return 0;
                }
                
                // For values that fit in positive int range, use nextInt for efficiency
                if (limit <= Integer.MAX_VALUE) {
                        return secureRandom.nextInt((int) limit);
                }
                
                // For larger values, use rejection sampling to avoid modulo bias
                long result;
                long maxValid = (Long.MAX_VALUE / limit) * limit;
                do {
                        result = secureRandom.nextLong() & Long.MAX_VALUE; // Keep positive
                } while (result >= maxValid);
                
                return result % limit;
        }

        //Performs the miller-rabin primality test on a guessed prime n.
        //trials is the number of attempts to verify this, because the function
        //is not 100% accurate it may be a composite.  However setting the trial
        //value to around 5 should guarantee success even with very large primes
        private boolean millerRabin (long n, int trials) { 
                long a = 0; 

                for (int i = 0; i < trials; i++) { 
                        a = rng(n - 3) + 2;// gets random value in [2..n-1] 
                        if (XpowYmodN(a, n - 1, n) != 1) return false; //n composite, return false 
                }
                return true; // n probably prime 
        } 

        //Generates a large prime number by
        //choosing a randomly large integer, and ensuring the value is odd
        //then uses the miller-rabin primality test on it to see if it is prime
        //if not the value gets increased until it is prime
        private long generatePrime() {
                long prime = 0;

                do {
                        long start = rng(maxNum);
                        prime = tryToGeneratePrime(start);
                } while (prime == 0);
                return prime;
        }
         
        private long tryToGeneratePrime(long prime) {
                //ensure it is an odd number
                if ((prime & 1) == 0)
                        prime += 1;

                long cnt = 0;
                while (!millerRabin(prime, 25) && (cnt++ < DH_RANGE) && prime < maxNum) {
                        prime += 2;
                        if ((prime % 3) == 0) prime += 2;
                }
                return (cnt >= DH_RANGE || prime >= maxNum) ? 0 : prime;
        }
         
        //Raises X to the power Y in modulus N
        //the values of X, Y, and N can be massive, and this can be 
        //achieved by first calculating X to the power of 2 then 
        //using power chaining over modulus N
        private long XpowYmodN(long x, long y, long N) {
                long result = 1;
                final long oneShift63 = ((long) 1) << 63;

                for (int i = 0; i < 64; y <<= 1, i++){
                        result = result * result % N;
                        if ((y & oneShift63) != 0)
                                result = result * x % N;
                }
                return result;
        }

        public void createKeys() {
                gen = generatePrime();
                mod = generatePrime();

                if (gen > mod) {
                        long swap = gen;
                        gen  = mod;
                        mod  = swap;
                }
        }

        public long createInterKey() {
                priv = rng(maxNum);
                return pub = XpowYmodN(gen,priv,mod);
        }

        public long createEncryptionKey(long interKey) throws Exception {
                if (interKey >= maxNum){
                        throw new Exception("interKey too large");
                }
                
                // Validate peer public value is in valid range to prevent attacks
                // Must be: 1 < interKey < modulus - 1
                if (interKey <= 1)
                        throw new Exception("Peer public value too small (must be > 1). Possible attack detected.");
                
                if (interKey >= mod - 1)
                        throw new Exception("Peer public value too large (must be < modulus - 1). Possible attack detected.");
                
                // Additional check: ensure interKey is not equal to generator (would reveal private key)
                if (interKey == gen)
                        throw new Exception("Peer public value equals generator. Possible attack detected.");
                
                return key = XpowYmodN(interKey,priv,mod);
        }


        public long getValue(int flags) {
                switch (flags) {
                        case DH_MOD:
                                return mod;
                        case DH_GEN:
                                return gen;
                        case DH_PRIV:
                                return priv;
                        case DH_PUB:
                                return pub;
                        case DH_KEY:
                                return key;
                        default:
                                return (long) 0;
                }
        }

        public int bits(long number){
                for (int i = 0; i < 64; i++){
                        number /= 2;
                        if (number < 2) return i;
                }
                return 0;
        }

        public static byte[] longToBytes(long number) {
                byte[] bytes  = new byte[8];
                for (int i = 0; i < 8; i++) {
                        bytes[i] = (byte) (0xff & (number >> (8 * (7 - i))));
                }
                return bytes;
        }

        public static long bytesToLong(byte[] bytes) {
                long result = 0;
                for (int i = 0; i < 8; i++) {
                        result <<= 8;
                        result += (byte) bytes[i];
                }
                return result;
        }

        private long gen;
        private long mod;
        private long priv;
        private long pub;
        private long key;
        private long maxNum;

        private static final int DH_MAX_BITS = 31;
        private static final int DH_RANGE = 100;

        private static final int DH_MOD  = 1;
        private static final int DH_GEN  = 2;
        private static final int DH_PRIV = 3;
        private static final int DH_PUB  = 4;
        private static final int DH_KEY  = 5;

}