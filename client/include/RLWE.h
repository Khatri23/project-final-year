#pragma once
#include<vector>
#include<cmath>
#include<memory>
using std::vector;
//define the parameter of original RLWE
class Original_parameter{
public:
    const int prime=3329;//int takes 32 bits
    const int degree=32; // degree of polynomial is 31 | 32 bit of secrets
    const int p_=3327;// 3329 inv in 4096 is 769 and -ve of 796 is 3327 
    const int omega=2532;// primitive 32 th root of unity but because of butterfly we will generate degree/2 omegas
    const int invOmega=2786;
    const int invdegree=128;//its in montgomery domain 3225
    int monte_bits=12;
    int bitmask=4095;
    int*Omegas;
    int* InvOmegas;
    Original_parameter():Omegas(new int[16]),InvOmegas(new int[16]){
        Omegas[0]=InvOmegas[0]=1;
        Omegas[1]=omega,InvOmegas[1]=invOmega;
        const int a=1237;//montgomery domain for omega (2532*4096)%3329
        const int b=2973;
        for(int i=2;i<16;i++){//successive power of omegas
            Omegas[i]=Omegas[i-1]*a;
            Omegas[i]=montpr(Omegas[i]);
            InvOmegas[i]=InvOmegas[i-1]*b;
            InvOmegas[i]=montpr(InvOmegas[i]);
        }
    }
    ~Original_parameter(){
        delete[]Omegas;
        delete[]InvOmegas;
    }
    //montogomery reduction
    int montpr(int& t){
        int q=t*p_;
        q= q & bitmask;
        int u= (prime*q+t) >> monte_bits;
        if( u >= prime) u-=prime;
        return u;
    }
    //modular exponential and flag indicate to set in montgomery domain or not
    int modular_exponential(const int& a, int& power,bool flag){
        int d=767;// montgomery domain (1 * 4096)% prime
        if(a==1){
            return (flag)?d:a;
        }
        int a_=(a << monte_bits)% prime; //barret reduction would be better but for 64 bit wordsize and small prime i am using naive %
        if(power <=1){
            return (flag)?a_:a;
        }
        short b=log2(power);
        while(b >=0){
            d=d*d;
            d=montpr(d);
            if((power >> b) & 1){
                d=d*a_;
                d=montpr(d); //d.a.r^-1 where r is 4096
            }
            b--;
        }
        return (flag)?d:montpr(d); //convert back to a.b mod p;
    }
    int get_degree() const {
        return degree;
    }
    int get_prime() const{
        return prime;
    }

};
std::shared_ptr<Original_parameter> initOP();//initialize the object for Original_parameters
   

class Rescale_parameter{
public:
    const int prime=1697;//int takes 32 bits
    const int degree=32; // degree of polynomial is 31 | 32 bit of secrets
    const int p_=671;// 1697 inv in 2048 is 1377 and -ve is 67 
    const int omega=69;// primitive 32 th root of unity but because of butterfly we will generate degree/2 omegas
    const int invOmega=910;
    const int invdegree=64;//its in montgomery domain 1644
    int monte_bits=11;
    int bitmask=2047;
    int*Omegas;
    int* InvOmegas;
    Rescale_parameter():Omegas(new int[16]),InvOmegas(new int[16]){
        Omegas[0]=InvOmegas[0]=1;
        Omegas[1]=omega,InvOmegas[1]=invOmega;
        const int a=461;//montgomery domain for omega (69*2048)%1697
        const int b=374;
        for(int i=2;i<16;i++){//successive power of omegas
            Omegas[i]=Omegas[i-1]*a;
            Omegas[i]=montpr(Omegas[i]);
            InvOmegas[i]=InvOmegas[i-1]*b;
            InvOmegas[i]=montpr(InvOmegas[i]);
        }
    }
    ~Rescale_parameter(){
        delete[]Omegas;
        delete[]InvOmegas;
    }
    //montogomery reduction
    int montpr(int& t){
        int q=t*p_;
        q= q & bitmask;
        int u= (prime*q+t) >> monte_bits;
        if( u >= prime) u-=prime;
        return u;
    }
     //modular exponential and flag indicate to set in montgomery domain or not
    int modular_exponential(const int& a, int& power,bool flag){
        int d=351;// montgomery domain (1 * 2048)% prime
        if(a==1){
            return (flag)?d:a;
        }
        int a_=(a << monte_bits)% prime; //barret reduction would be better but for 64 bit wordsize and small prime i am using naive %
        if(power <=1){
            return (flag)?a_:a;
        }
        short b=log2(power);
        while(b >=0){
            d=d*d;
            d=montpr(d);
            if((power >> b) & 1){
                d=d*a_;
                d=montpr(d); //d.a.r^-1 where r is 4096
            }
            b--;
        }
        return (flag)?d:montpr(d); //convert back to a.b mod p;
    }

    int get_degree() const {
        return degree;
    }
    int get_prime() const{
        return prime;
    }
};
std::shared_ptr<Rescale_parameter> initRP(); //initialize the object for Original_parameters
    

int bit_reversal(int,int);
template<typename T>
void NTT(vector<int>&,vector<int>&, const std::shared_ptr<Original_parameter>&, bool);

template<typename T>
void polynomial_multiplication(vector<int>&,vector<int>&,vector<int>&, const std::shared_ptr<Original_parameter>&);

template<typename T>
void polynomial_addition(vector<int>&,vector<int>&,vector<int>&, const std::shared_ptr<Original_parameter>&);

template<typename T>
void polynomial_subtraction(vector<int>&,vector<int>&,vector<int>&, const std::shared_ptr<Original_parameter>&);
#include"rust/cxx.h"
#include "client/src/main.rs.h"
struct Cipher;
Cipher RLWE_EncryptOP(const rust::Vec<int>&,rust::Vec<int>, const std::shared_ptr<Original_parameter>&);
rust::Vec<int> RLWE_DecryptOP(const rust::Vec<int>&,const Cipher&,const std::shared_ptr<Original_parameter>&);

Cipher RLWE_EncryptRP(const rust::Vec<int>&,rust::Vec<int>, const std::shared_ptr<Rescale_parameter>&);
rust::Vec<int> RLWE_DecryptRP(const rust::Vec<int>&,const Cipher&,const std::shared_ptr<Rescale_parameter>&);