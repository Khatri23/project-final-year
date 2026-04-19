#include"client/include/RLWE.h"
#include<functional>
int bit_reversal(int x,int n){
    //reverse a bit
    int r=0;
    while(n--){
        r=(r << 1)|(x & 1);
        x=x >> 1;
    }
    return r;
}

//FFT->(polynomial multiplication) purpose is to evaluate using CT butterfly result size should be allocated manually
template<typename T>
void NTT(vector<int>&result,vector<int>&a, const std::shared_ptr<T>& obj,bool inverse){
    int stride=1;
    int power=obj->degree >> 1;
    result[0]=a[0];//a0,a16
    for(int i=1;i<obj->degree;i++){
        result[i]=a[bit_reversal(i,5)];//log(32) reversing the 5 bits value
    }
    int * Omegas=(inverse)?obj->InvOmegas:obj->Omegas;
    while(stride < obj->degree)
    {
        for(int start=0;start < obj->degree;start+=stride << 1){
            int end=start+stride,om=0;
            for(int i=start;i<end;i++){
                //apply the CT butterfly a+bw and a-bw
                int zp=obj->modular_exponential(Omegas[om++],power,true);
                int a=result[i];
                int b=result[i+stride]*zp;
                b=obj->montpr(b);
                result[i]=a+b;
                if(result[i] >= obj->prime) result[i]-=obj->prime;
                result[i+stride]=a-b;
                if(result[i+stride] < 0) result[i+stride]+=obj->prime;
            }
        }
        stride =stride << 1;
        power=power >> 1;
    }
}

template<typename T>
void polynomial_multiplication(vector<int>&result,vector<int>&a,vector<int>&b, const std::shared_ptr<T>& obj)
{
    vector<int>a_eval,b_eval;
    a_eval.resize(obj->degree),b_eval.resize(obj->degree);
    NTT(a_eval,a,obj,false);//Forward NTT of a;
    NTT(b_eval,b,obj,false);//forward NTT of b;
    vector<int>out(obj->degree);
    result.resize(obj->degree);
    for(int i=0;i<obj->degree;i++){ //point wise multiplication
        //set a_eval to montgomery domain it sounds silly since we are doing a.r % prime and prime is small
        //but also we will use it as when prime is too large it yeild significant performance
        a_eval[i]=(a_eval[i] <<obj->monte_bits) %obj->prime;//barret reduction 
        out[i]=a_eval[i]*b_eval[i];
        out[i]=obj->montpr(out[i]);
    }
    //inverse FFT for the result
    NTT(result,out,obj,true);
    //multiply degree-1
    for(auto &x: result){
        x=x*obj->invdegree;
        x=obj->montpr(x);
    }
}

//result must be resize to degree before using adds the coefficient of the polynomial
template<typename T>
void polynomial_addition(vector<int>&result,vector<int>&a,vector<int>&b, const std::shared_ptr<T>& obj){
    for(int i=0;i<obj->degree;i++){
        result[i]=a[i]+b[i];
        if(result[i] >=obj->prime) result[i]-=obj.get()->prime;
    }
}
//result must be resize to degree before using sub the coefficient of polynomials
template<typename T>
void polynomial_subtraction(vector<int>&result,vector<int>&a,vector<int>&b, const std::shared_ptr<T>& obj){
    for(int i=0;i<obj->degree;i++){
        result[i]=a[i]-b[i];
        if(result[i] < 0) result[i]+=obj->prime;
    }
}
//RLWE encryption: expect array of scaled message output <a,b=s.a+m+e> only for original parameter
Cipher RLWE_EncryptOP(const rust::Vec<int>& secret,rust::Vec<int>message, const std::shared_ptr<Original_parameter>&obj){
    auto e=small_rand();
    vector<int>error,aa,s,msg;
    std::copy(e.begin(),e.end(),std::back_inserter(error));//copy Vec -> vector
    auto a=big_rand(obj->get_prime(),obj->get_degree());
    std::copy(a.begin(),a.end(),std::back_inserter(aa));
    std::copy(secret.begin(),secret.end(),std::back_inserter(s));
    std::copy(message.begin(),message.end(),std::back_inserter(msg));
   
    vector<int>b;
    polynomial_multiplication(b,aa,s,obj);
    polynomial_addition(msg,msg,error,obj);
    polynomial_addition(b,b,msg,obj);
    rust::Vec<int>res;
    std::copy(b.begin(),b.end(),std::back_inserter(res));
    
    return Cipher{a,res};
} 

rust::Vec<int> RLWE_DecryptOP(const rust::Vec<int>&s,const Cipher& c,const std::shared_ptr<Original_parameter>&obj){
    vector<int>a,b,m,secret;
    std::copy(s.begin(),s.end(),std::back_inserter(secret)); //make compatible with c++ vectors;
    std::copy(c.a.begin(),c.a.end(),std::back_inserter(a));
    std::copy(c.b.begin(),c.b.end(),std::back_inserter(b));
    polynomial_multiplication(m,a,secret,obj);
    polynomial_subtraction(m,b,m,obj);
    int t=50; //plaintext modulo
    int sk=obj->prime/t;
    int rem_bound=sk/2; //if the remainder is > than half then ceil value
    for(auto &x:m)
    {
        // now do rounding to nearest multiple of sk
        int temp = x / sk;
        int rem = x - temp * sk;
        if (rem >= rem_bound) temp++;
        x = temp;
    }
    rust::Vec<int>result;
    std::copy(m.begin(),m.end(),std::back_inserter(result));
    return result;
}

//RLWE encryption: expect array of scaled message output <a,b=s.a+m+e> only for rescaled parameter
Cipher RLWE_EncryptRP(const rust::Vec<int>& secret,rust::Vec<int>message, const std::shared_ptr<Rescale_parameter>&obj){
    auto e=small_rand();
    vector<int>error,aa,s,msg;
    std::copy(e.begin(),e.end(),std::back_inserter(error));//copy Vec -> vector
    auto a=big_rand(obj->get_prime(),obj->get_degree());
    std::copy(a.begin(),a.end(),std::back_inserter(aa));
    std::copy(secret.begin(),secret.end(),std::back_inserter(s));
    std::copy(message.begin(),message.end(),std::back_inserter(msg));
   
    vector<int>b;
    polynomial_multiplication(b,aa,s,obj);
    polynomial_addition(msg,msg,error,obj);
    polynomial_addition(b,b,msg,obj);
    rust::Vec<int>res;
    std::copy(b.begin(),b.end(),std::back_inserter(res));
    
    return Cipher{a,res};
} 

rust::Vec<int> RLWE_DecryptRP(const rust::Vec<int>&s,const Cipher& c,const std::shared_ptr<Rescale_parameter>&obj){
    vector<int>a,b,m,secret;
    std::copy(s.begin(),s.end(),std::back_inserter(secret)); //make compatible with c++ vectors;
    std::copy(c.a.begin(),c.a.end(),std::back_inserter(a));
    std::copy(c.b.begin(),c.b.end(),std::back_inserter(b));
    polynomial_multiplication(m,a,secret,obj);
    polynomial_subtraction(m,b,m,obj);
    int t=50; //plaintext modulo
    int sk=obj->prime/t;
    int rem_bound=sk/2; //if the remainder is > than half then ceil value
    for(auto &x:m)
    {
        // now do rounding to nearest multiple of sk
        int temp = x / sk;
        int rem = x - temp * sk;
        if (rem >= rem_bound) temp++;
        x = temp;
    }
    rust::Vec<int>result;
    std::copy(m.begin(),m.end(),std::back_inserter(result));
    return result;
}

std::shared_ptr<Rescale_parameter> initRP() { //initialize the object for Original_parameters
    return std::shared_ptr<Rescale_parameter>(new Rescale_parameter());
}
std::shared_ptr<Original_parameter> initOP() { //initialize the object for Original_parameters
    return std::shared_ptr<Original_parameter>(new Original_parameter());
}


