#ifndef _ECC_H_
#define _ECC_H_

//----------------------------------------

#if BUILDING_DLL
#define DLLIMPORT __declspec(dllexport)
#else
#define DLLIMPORT __declspec(dllimport)
#endif

#define API __stdcall

//----------------------------------------

typedef unsigned int Bool;
typedef unsigned char Byte;
typedef unsigned short Digit_16;
typedef unsigned long Digit_32;
typedef unsigned long long Digit_64;

//----------------------------------------

#define Success 0
#define Fail -1

#define TURE 1
#define FALSE 0

#define NumSys_Bin 2
#define NumSys_Oct 8
#define NumSys_Dec 10
#define NumSys_Hex 16
#define NumSys_32 32
#define NumSys_62 62
#define NumSys_64 64

//----------------------------------------

#define ECC_ansip192k1 11921
#define ECC_ansip224r1 12241
#define ECC_ansip256k1 12561
#define ECC_ansip384r1 13841
#define ECC_brainpoolP224r1 22241
#define ECC_brainpoolP224t1 22242
#define ECC_gost256 52561
#define ECC_numsp256d1 62561
#define ECC_numsp384d1 63841
#define ECC_numsp512d1 65121
#define ECC_prime192v1 71921
#define ECC_prime192v2 71922
#define ECC_prime192v3 71923
#define ECC_prime256v1 72561
#define ECC_secp128r1 81281
#define ECC_sm2p256e 92561
#define ECC_sm2p256 92562

//----------------------------------------

#define Error_NULL 0

#define Error_MallocFail -5101

#define Error_Param_Text -5201
#define Error_Param_NumSys -5202
#define Error_Param_LargeNumber -5203


#define Error_Entropy_Uninit -5301
#define Error_Entropy_Lack -5302
#define Error_Entropy_Len -5313
#define Error_Entropy_Data -5314
#define Error_Entropy_MaxSize -5315

#define Error_ECC_Uninit -5401
#define Error_ECC_CurveID -5412
#define Error_ECC_Key -5413
#define Error_ECC_Buf -5414
#define Error_ECC_Msg -5415
#define Error_ECC_Signature -5416
#define Error_ECC_Digest -5417
#define Error_ECC_Len -5418
#define Error_ECC_dLen -5419
#define Error_ECC_ZeroPoint -5420
#define Error_ECC_Public -5421
#define Error_ECC_Private -5422
#define Error_ECC_Unknown -5932

//----------------------------------------

typedef struct SM3Context       //SM3上下文
{
    Digit_32 iHash[8];
    Byte Block[64];
}SM3Context;

typedef struct LargeNumber
{
    Digit_32 Len;               //Data的长度
    Digit_32 MSB;               //Most Significant Bit
    Digit_32 Size;              //当MSB不等于0时，MSB等于(MSB+31)>>5；当MSB等于0时，MSB等于1
    Digit_32 *Data;
}s_LN;

typedef s_LN *LN;

typedef struct Point            //仿射坐标系下的点
{
    s_LN X;
    s_LN Y;
}s_Point;

typedef s_Point *Point;

typedef struct JPoint           //Jacobi坐标系下的点
{
    s_LN X;
    s_LN Y;
    s_LN Z;
}s_JPoint;

typedef s_JPoint *JPoint;

typedef struct CurveParam
{
    s_LN P;
    s_LN A;
    s_LN B;
    s_LN N;
    s_LN D;
    s_LN PT;
    s_LN NT;
    s_Point G;
    s_Point Public;
}CurveParam;

typedef struct LNT
{
    s_LN TempMul0;
    s_LN TempMul1;
    s_LN TempDiv0;
    s_LN TempMod0;
    s_LN TempMod1;
    s_LN TempMod2;
    s_LN TempMod3;
    s_LN TempInv0;
    s_LN TempInv1;
    s_LN TempInv2;
    s_LN Temp;
}LNT;

typedef struct CurveT
{
    s_LN Temp0;
    s_LN Temp1;
    s_LN Temp2;
    s_LN Temp3;
    s_LN Temp4;
    s_LN Temp5;
    s_Point TempP0;
    s_Point TempP1;
    s_JPoint TempJ0;
    s_JPoint TempJ1;
}CurveT;

typedef struct CurveContext
{
    Digit_32 ID;
    Digit_32 Bit;
    Bool IsCulPublic;
    Bool IsInputSign;
    Byte *CipherText;
    Byte *PlainText;
    Byte *DigestText;
    Digit_32 CipherTextLen;
    Digit_32 PlainTextLen;
    Byte Sign[32];
    CurveParam Param;
    CurveT CurveTemp;
    LNT LNTemp;
    Digit_32 *FreePointer;
}*CurveContext;

typedef struct Entropy
{
    Byte *Lib;
    Digit_32 Size;
    Digit_32 MaxSize;
}*Entropy;

//----------------------------------------

DLLIMPORT int API GetLastErrorCode();

DLLIMPORT int API SM3(Byte *Msg,int Len,Byte R[32]);

DLLIMPORT int API SHA256(Byte *Msg,long long Len,Byte R[32]);

DLLIMPORT int API SM2_KDF_SM3(Byte *Msg,int Len,Byte *R,int Size);

DLLIMPORT int API SM2_KDF_SHA256(Byte *Msg,int Len,Byte *R,int Size);

//----------------------------------------

DLLIMPORT Entropy API EntropyLibInit(int MaxSize);

DLLIMPORT int API EntropyLibFree(Entropy src);

DLLIMPORT int API EntropyLibEmpty(Entropy src);

DLLIMPORT int API EntropyLibInput(Entropy src,Byte *Data,int Len);

DLLIMPORT int API EntropyLibGetSize(Entropy src);

//----------------------------------------

DLLIMPORT CurveContext API EccInit(int CurveID);

DLLIMPORT int API EccFree(CurveContext Curve);

DLLIMPORT int API EccFreeCache(CurveContext Curve);

DLLIMPORT int API EccPrivateKeyGenFromEntropy(CurveContext Curve);

DLLIMPORT int API EccInputPrivateKey(CurveContext Curve,char *Key,int Len);

DLLIMPORT int API EccInputPublicKey(CurveContext Curve,char *Key,int Len);

DLLIMPORT int API EccCulPublicKey(CurveContext Curve);

DLLIMPORT int API EccGetCurveBit(CurveContext Curve);

DLLIMPORT int API EccOutputPrivateKey(CurveContext Curve,char *Buf,int Len);

DLLIMPORT int API EccOutputPublicKey(CurveContext Curve,char *Buf,int Len);

DLLIMPORT int API EccEncrypt(CurveContext Curve,Byte *Msg,int Len);

DLLIMPORT int API EccGetCipherText(CurveContext Curve,Byte *Buf,int Len);

DLLIMPORT int API EccDecrypt(CurveContext Curve,Byte *Msg,int Len);

DLLIMPORT int API EccGetPlainText(CurveContext Curve,Byte *Buf,int Len);

DLLIMPORT int API EccInputSignatere(CurveContext Curve,Byte *Signature,int Len);

DLLIMPORT int API EccDigest(CurveContext Curve,Byte *Msg,int Len);

DLLIMPORT int API EccGetDigestText(CurveContext Curve,Byte *Buf,int Len);

DLLIMPORT int API EccVerify(CurveContext Curve,Byte *Msg,int Len,Byte *Digest,int dLen);

//----------------------------------------

#endif