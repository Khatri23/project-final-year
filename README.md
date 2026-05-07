The core logic is written in C++, Inside client you get RLWE.h(include) and RLWE.cc(src). For experimenting purpose i have choosen two primes
3329 and 1697 both are NTT friendly prime and dimension (n) =32, It works in canonical residue system, It is enough to follow these cpp file to
understand the basic of RLWE encryption. Note that error is randomly sampled from unsigned 32 bit number and taken its bits, message encoding uses
single value binary decomposition where my implementation is restricted for 32 bit integers. Actually I have simulated client-server interaction 
which has clear seperation of concern about what client does and what server does. Server is responsible for performing homomorphic operation. 
I had also tried modulus switching but decryption didn't work (I guess may be affected by residue class).

Actually the concept is important than the implementation. The best starting point is RSA and ELGAMAL encryption and exploring how it fits for 
partial homomorphic encryption(multiplication) and Paillier (additive homomorphic encryption).
Polynomial multiplication uses Number Theoretic Transformation(NTT) where we compute Discret Fourier Transform (DFT) by evaluating the polynomial at 
nth root of unity since the polynomial modulo is (x^n-1). If polynomial modulo is (x^n+1) we require 2nth root of unity.
