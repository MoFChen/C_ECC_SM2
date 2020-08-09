#include "ecc.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

//----------------------------------------

static Byte Base16[16]="0123456789ABCDEF";
//static Byte Base32[32]="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
//static Byte Base64[64]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int CurveIDList[17]={11921,12241,12561,13841,22241,22242,52561,62561,63841,65121,71921,71922,71923,72561,81281,92561,92562};

static Digit_32 LastErrorCode=Error_NULL;

//----------------------------------------

int CheckText(char *Text,int Len)
{
    //检查参数
    if(Text==NULL)
    {
        LastErrorCode=Error_Param_Text;
        return Fail;
    }
    if(Len<=0)return Fail;
    //判断文本
    int i;
    for(i=0;i<Len;i++)
    {
        if(Text[i]<48||(Text[i]>57&&Text[i]<65)||Text[i]>70)return Fail;
    }
    return Success;
}

Digit_32 CharToNum(char src)
{
    if(src<=57)return src-48;
    return src-55;
}

Digit_32 TextToNumber(char *src,int Len)
{
    int i;
    Digit_32 temp=0;
    for(i=0;i<Len;i++)
    {
        temp*=10;
        temp+=(src[i]-48);
    }
    return temp;
}

int TenPower(int index)
{
    int temp=1,i;
    for(i=0;i<index;i++)temp*=10;
    return temp;
}

//----------------------------------------

//向左循环移位
#define LeftRotate(digit32,bits) ((digit32)<<(bits)|(digit32)>>(32-(bits)))

#define SHA256_ROTL(a,b) (((a>>(32-b))&(0x7FFFFFFF>>(31-b)))|(a<<b))
#define SHA256_SR(a,b) ((a>>b)&(0x7FFFFFFF>>(b-1)))
#define SHA256_Ch(x,y,z) ((x&y)^((~x)&z))
#define SHA256_Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define SHA256_E0(x) (SHA256_ROTL(x,30)^SHA256_ROTL(x,19)^SHA256_ROTL(x,10))
#define SHA256_E1(x) (SHA256_ROTL(x,26)^SHA256_ROTL(x,21)^SHA256_ROTL(x,7))
#define SHA256_O0(x) (SHA256_ROTL(x,25)^SHA256_ROTL(x,14)^SHA256_SR(x,3))
#define SHA256_O1(x) (SHA256_ROTL(x,15)^SHA256_ROTL(x,13)^SHA256_SR(x,10))

Digit_32 *ReverseWord(Digit_32 *word)
{
    Byte *byte=(Byte*)word,temp;

    temp=byte[0];
    byte[0]=byte[3];
    byte[3]=temp;

    temp=byte[1];
    byte[1]=byte[2];
    byte[2]=temp;

    return word;
}

Digit_32 T(int i)
{
    if(i>=0&&i<=15)return 0x79CC4519;
    else if(i>=16&&i<=63)return 0x7A879D8A;
    else return 0;
}

Digit_32 FF(Digit_32 X,Digit_32 Y,Digit_32 Z,int i)
{
    if(i>=0&&i<=15)return X^Y^Z;
    else if(i>=16&&i<=63)return (X&Y)|(X&Z)|(Y&Z);
    else return 0;
}

Digit_32 GG(Digit_32 X,Digit_32 Y,Digit_32 Z,int i)
{
    if(i>=0&&i<=15)return X^Y^Z;
    else if(i>=16&&i<=63)return (X&Y)|(~X&Z);
    else return 0;
}

Digit_32 P0(Digit_32 X)
{
    return X^LeftRotate(X,9)^LeftRotate(X,17);
}

Digit_32 P1(Digit_32 X)
{
    return X^LeftRotate(X,15)^LeftRotate(X,23);
}

void SM3Init(SM3Context *context)
{
    context->iHash[0]=0x7380166F;
    context->iHash[1]=0x4914B2B9;
    context->iHash[2]=0x172442D7;
    context->iHash[3]=0xDA8A0600;
    context->iHash[4]=0xA96F30BC;
    context->iHash[5]=0x163138AA;
    context->iHash[6]=0xE38DEE4D;
    context->iHash[7]=0xB0FB0E4E;
}

void SM3Process(SM3Context *context)
{
    int i;
    Digit_32 W[68],W_[64],W__[8],SS1,SS2,TT1,TT2;

    /* 消息扩展 */
    for(i=0;i<16;i++)
    {
        W[i]=*(Digit_32*)(context->Block+i*4);
        ReverseWord(W+i);
    }
    for(i=16;i<68;i++)
    {
        W[i]=P1(W[i-16]^W[i-9]^LeftRotate(W[i-3],15))^LeftRotate(W[i-13],7)^W[i-6];
    }
    for(i=0;i<64;i++)
    {
        W_[i]=W[i]^W[i+4];
    }

    /* 消息压缩 */
    for(i=0;i<8;i++)W__[i]=context->iHash[i];

    for(i=0;i<64;i++)
    {
        SS1=LeftRotate((LeftRotate(W__[0],12)+W__[4]+LeftRotate(T(i),i)),7);
        SS2=SS1^LeftRotate(W__[0],12);
        TT1=FF(W__[0],W__[1],W__[2],i)+W__[3]+SS2+W_[i];
        TT2=GG(W__[4],W__[5],W__[6],i)+W__[7]+SS1+W[i];
        W__[3]=W__[2];
        W__[2]=LeftRotate(W__[1],9);
        W__[1]=W__[0];
        W__[0]=TT1;
        W__[7]=W__[6];
        W__[6]=LeftRotate(W__[5],19);
        W__[5]=W__[4];
        W__[4]=P0(TT2);
    }

    for(i=0;i<8;i++)context->iHash[i]^=W__[i];
}

void MemCopy(Byte *dest,Byte *src,Digit_32 size)
{
    Digit_32 i;
    for(i=0;i<size;i++)dest[i]=src[i];
}

void MemSet(Byte *dest,Byte val,Digit_32 size)
{
    Digit_32 i;
    for(i=0;i<size;i++)dest[i]=val;
}

int SM3T(Byte *Msg,Digit_32 Len,Byte R[32])
{
    SM3Context context;
    Digit_32 i,r,bitLen;

    //初始化
    SM3Init(&context);

    //消息分组处理
    Digit_32 L=Len>>6;
    for(i=0;i<L;i++)
    {
        MemCopy(context.Block,Msg+(i<<6),64);
        SM3Process(&context);
    }

    //填充消息分组
    bitLen=Len>>3;
    ReverseWord(&bitLen);
    r=Len&63;
    MemCopy(context.Block,Msg+(i<<6),r);
    context.Block[r]=0x80;
    if (r<=55)
    {
        //只考虑长度在(2^32)-1以内的情况，故将高4个字节赋为0
        MemSet(context.Block+r+1,0,59-r);
        MemCopy(context.Block+60,(Byte*)&bitLen,4);
        SM3Process(&context);
    }
    else
    {
        MemSet(context.Block+r+1,0,63-r);
        SM3Process(&context);
        //只考虑长度在(2^32)-1以内的情况，故将高4个字节赋为0
        MemSet(context.Block,0,60);
        MemCopy(context.Block+60,(Byte*)&bitLen,4);
        SM3Process(&context);
    }

    //返回结果
    for(i=0;i<8;i++)ReverseWord(context.iHash+i);
    MemCopy(R,(Byte*)context.iHash,32);

    return Success;
}

int SHA256T(Byte *Msg,Digit_64 Len,Byte R[32])
{
    char *pp,*ppend;
    long l,i,W[64],T1,T2,A,B,C,D,E,F,G,H;
    long U[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    long K[64] = 
    {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    };
    l=Len+((Len%64>=56)?(128-Len%64):(64-Len%64));
    if(!(pp=(char*)malloc((Digit_32)l)))return Fail;
    for(i=0;i<Len;pp[i+3-2*(i%4)]=Msg[i],i++);
    for(pp[i+3-2*(i%4)]=128,i++;i<l;pp[i+3-2*(i%4)]=0,i++);
    *((long*)(pp+l-4))=Len<<3;
    *((long*)(pp+l-8))=Len>>29;
    for (ppend=pp+l;pp<ppend;pp+=64)
    {
        for(i=0;i<16;W[i]=((long*)pp)[i],i++);
        for(i=16;i<64;W[i]=(SHA256_O1(W[i-2])+W[i-7]+SHA256_O0(W[i-15])+W[i-16]),i++);
        A=U[0],B=U[1],C=U[2],D=U[3],E=U[4],F=U[5],G=U[6],H=U[7];
        for (i=0;i<64;i++)
        {
            T1=H+SHA256_E1(E)+SHA256_Ch(E,F,G)+K[i]+W[i];
            T2=SHA256_E0(A)+SHA256_Maj(A,B,C);
            H=G,G=F,F=E,E=D+T1,D=C,C=B,B=A,A=T1+T2;
        }
        U[0]+=A,U[1]+=B,U[2]+=C,U[3]+=D,U[4]+=E,U[5]+=F,U[6]+=G,U[7]+=H;
    }
    free(pp-l);

    Digit_32 *temp=(Digit_32*)R;
    for(i=0;i<8;i++)
    {
        ReverseWord(U+i);
        temp[i]=U[i];
    }
    return Success;
}

int KDFFromSM3(Byte *Msg,int Len,int kLen,Byte *R)
{
    if(Msg==NULL||Len<0||kLen<0)return Fail;

    Byte *pRet=(Byte*)malloc(kLen),*pData=(Byte*)malloc(Len+4);
    if(pRet==NULL||pData==NULL)
    {
        if(pRet!=NULL)free(pRet);
        if(pData!=NULL)free(pData);
        return Fail;
    }

    MemSet(pRet,0,kLen);
    MemSet(pData,0,Len+4);

    Byte cAbs[32]={0};              //摘要
    Byte cCnt[4]={0};               //计数器的内存表示值
    int nCnt=1;                     //计数器
    Byte *pCnt=(Byte*)&nCnt;        //计数器地址
    int nAbs=32;                    //摘要长度
    int nTimes=(kLen+31)>>5;        //需要计算的次数
    int i=0;
    MemCopy(pData,Msg,Len);
    for(i=0;i<nTimes;i++)
    {
        //cCnt
        {
            cCnt[0]=(nCnt>>24)&0xFF;
            cCnt[1]=(nCnt>>16)&0xFF;
            cCnt[2]=(nCnt>> 8)&0xFF;
            cCnt[3]=(nCnt    )&0xFF;
        }

        MemCopy(pData+Len,cCnt,4);
        SM3T(pData,Len+4,cAbs);

        if(i==nTimes-1)             //最后一次计算，根据keylen/32是否整除，截取摘要的值
        {
            if((kLen&31)!=0)nAbs=kLen&31;
        }
        MemCopy(pRet+(i>>5),cAbs,nAbs);
        i++;
        nCnt++;
    }
    if(R!=NULL)MemCopy(R,pRet,kLen);

    return Success;
}

int KDFFromSHA256(Byte *Msg,int Len,int kLen,Byte *R)
{
    if(Msg==NULL||Len<0||kLen<0)return Fail;

    Byte *pRet=(Byte*)malloc(kLen),*pData=(Byte*)malloc(Len+4);
    if(pRet==NULL||pData==NULL)
    {
        if(pRet!=NULL)free(pRet);
        if(pData!=NULL)free(pData);
        return Fail;
    }

    MemSet(pRet,0,kLen);
    MemSet(pData,0,Len+4);

    Byte cAbs[32]={0};              //摘要
    Byte cCnt[4]={0};               //计数器的内存表示值
    int nCnt=1;                     //计数器
    Byte *pCnt=(Byte*)&nCnt;        //计数器地址
    int nAbs=32;                    //摘要长度
    int nTimes=(kLen+31)>>5;        //需要计算的次数
    int i=0;
    MemCopy(pData,Msg,Len);
    for(i=0;i<nTimes;i++)
    {
        //cCnt
        {
            cCnt[0]=(nCnt>>24)&0xFF;
            cCnt[1]=(nCnt>>16)&0xFF;
            cCnt[2]=(nCnt>> 8)&0xFF;
            cCnt[3]=(nCnt    )&0xFF;
        }

        MemCopy(pData+Len,cCnt,4);
        SHA256T(pData,(Digit_64)(Len+4),cAbs);

        if(i==nTimes-1)             //最后一次计算，根据keylen/32是否整除，截取摘要的值
        {
            if((kLen&31)!=0)nAbs=kLen&31;
        }
        MemCopy(pRet+(i>>5),cAbs,nAbs);
        i++;
        nCnt++;
    }
    if(R!=NULL)MemCopy(R,pRet,kLen);

    return Success;
}

//----------------------------------------

int LnCulMSB(LN src)
{
    int i,j;
    Digit_32 temp;
    for(i=src->Len-1;i>=0;i--)
    {
        if(src->Data[i]!=0)
        {
            for(j=1;j<32;j++)
            {
                temp=src->Data[i]>>j;
                if(temp==0)
                {
                    src->MSB=(i<<5)+j;
                    src->Size=i+1;
                    return Success;
                }
            }
            src->MSB=(i+1)<<5;
            src->Size=i+1;
            return Success;
        }
    }
    src->MSB=0;
    src->Size=1;
    return Success;
}

int LnPrint(LN src)
{
    if(src==NULL)return Fail;
    printf("\nPrintTest:\n");
    printf("Len:%u\nSize:%u\nMSB:%u\nData:\n",src->Len,src->Size,src->MSB);
    int i;
    for(i=0;i<src->Size;i++)
    {
        printf("%08X,%u\n",src->Data[i],src->Data[i]);
    }
    printf("\n");
    return Success;
}


int LnZero(LN src)
{
    //大数清零
    int i,L=src->Len;
    for(i=0;i<L;i++)src->Data[i]=0;
    src->MSB=0;
    src->Size=0;
    return Success;
}

int LnAssign(LN src,LN dest)
{
    //判断是否超出空间
    if(src->Len<dest->Size)
    {
        LastErrorCode=Error_Param_LargeNumber;
        return Fail;
    }
    //开始赋值
    int i,L=dest->Size;
    if(src->MSB!=0)LnZero(src);
    for(i=0;i<L;i++)src->Data[i]=dest->Data[i];
    src->MSB=dest->MSB;
    src->Size=dest->Size;
    return Success;
}

int LnAssignBit(LN src,LN dest,Digit_32 bits)
{
    LnZero(src);
    Digit_32 r=bits>>5,s=bits&31,i=0,t;
    for(i=0;i<r;i++)
    {
        src->Data[i]=dest->Data[i];
    }
    if(s==0)
    {
        LnCulMSB(src);
        return Success;
    }
    t=(1ULL<<s)-1;
    src->Data[i]=dest->Data[i]&t;
    LnCulMSB(src);
    return Success;
}


int LnGreater(LN src1,LN src2)
{
    if(src1->MSB>src2->MSB)return TURE;
    if(src1->MSB<src2->MSB)return FALSE;
    int i;
    for(i=src1->Size-1;i>=0;i--)
    {
        if(src1->Data[i]>src2->Data[i])return TURE;
        if(src1->Data[i]<src2->Data[i])return FALSE;
    }
    return FALSE;
}

int LnGreaterEqual(LN src1,LN src2)
{
    if(src1->MSB>src2->MSB)return TURE;
    if(src1->MSB<src2->MSB)return FALSE;
    int i;
    for(i=src1->Size-1;i>=0;i--)
    {
        if(src1->Data[i]>src2->Data[i])return TURE;
        if(src1->Data[i]<src2->Data[i])return FALSE;
    }
    return TURE;
}

int LnEqual(LN src1,LN src2)
{
    if(src1->MSB!=src2->MSB)return FALSE;
    int i;
    for(i=src1->Size-1;i>=0;i--)
    {
        if(src1->Data[i]!=src2->Data[i])return FALSE;
    }
    return TURE;
}

int LnLess(LN src1,LN src2)
{
    if(src1->MSB>src2->MSB)return FALSE;
    if(src1->MSB<src2->MSB)return TURE;
    int i;
    for(i=src1->Size-1;i>=0;i--)
    {
        if(src1->Data[i]>src2->Data[i])return FALSE;
        if(src1->Data[i]<src2->Data[i])return TURE;
    }
    return FALSE;
}

int LnLessEqual(LN src1,LN src2)
{
    if(src1->MSB>src2->MSB)return FALSE;
    if(src1->MSB<src2->MSB)return TURE;
    int i;
    for(i=src1->Size-1;i>=0;i--)
    {
        if(src1->Data[i]>src2->Data[i])return FALSE;
        if(src1->Data[i]<src2->Data[i])return TURE;
    }
    return TURE;
}


int LnSetBit(LN src,Digit_32 Pos,int Bit)
{
    int p=Pos>>5,r=Pos&31;
    if(Bit==1)
    {
        src->Data[p]|=(1<<r);
    }
    else
    {
        src->Data[p]&=(~(1<<r));
    }
    LnCulMSB(src);
    return Success;
}

int LnGetBit(LN src,Digit_32 Pos)
{
    int p=Pos>>5,r=Pos&31;
    if((src->Data[p]&(1<<r))==0)return 0;
    return 1;
}

int LnMoveLeft(LN src,Digit_32 Bit)
{
    //判断特殊情况
    if(Bit==0||src->MSB==0)return Success;
    //判断是否超出空间
    Digit_32 L=(src->MSB+Bit+31)>>5;
    if(src->Len<L)
    {
        LastErrorCode=Error_Param_LargeNumber;
        return Fail;
    }
    //开始计算
    Digit_32 p=Bit>>5;
    Digit_32 r=Bit&31;
    int i;
    if(r==0)
    {
        for(i=src->Size-1;i>=0;i--)
        {
            src->Data[i+p]=src->Data[i];
            src->Data[i]=0;
        }
    }
    else
    {
        Digit_64 temp;
        for(i=src->Size-1;i>=0;i--)
        {
            temp=src->Data[i];
            src->Data[i]=0;
            temp<<=r;
            src->Data[i+p]=(Digit_32)temp;
            temp>>=32;
            if(temp!=0)src->Data[i+p+1]|=(Digit_32)temp;
        }
    }
    src->MSB+=Bit;
    src->Size=L;

    return Success;
}

int LnMoveRight(LN src,Digit_32 Bit)
{
    //判断特殊情况
    if(Bit==0||src->MSB==0)return Success;
    if(Bit>=src->MSB)
    {
        LnZero(src);
        return Success;
    }
    //开始计算
    Digit_32 L=src->Size;
    Digit_32 p=Bit>>5;
    Digit_32 r=Bit&31;
    int i;
    for(i=0;i<p;i++)src->Data[i]=0;
    if(r==0)
    {
        for(i=p;i<L;i++)
        {
            src->Data[i-p]=src->Data[i];
            src->Data[i]=0;
        }
    }
    else
    {
        Digit_64 temp;
        for(i=p;i<L;i++)
        {
            temp=src->Data[i];
            src->Data[i]=0;
            temp<<=(32-r);
            if(i>p)src->Data[i-p-1]|=(Digit_32)temp;
            temp>>=32;
            src->Data[i-p]=(Digit_32)temp;
        }
    }
    src->MSB-=Bit;
    src->Size=(src->MSB+31)>>5;
    return Success;
}

int LnMoveRightOne(LN src)
{
    if(src->MSB==0)return Success;
    int i,j;
    Digit_32 cache;
    i=src->Size;
    do
    {
        i--;
        cache=src->Data[i];
        if(j==1)src->Data[i]=(0x80000000)|(src->Data[i]>>1);
        else src->Data[i]>>=1;
        j=cache&1;
    }while(i!=0);
    LnCulMSB(src);
    return Success;
}


int LnPlusInt(LN src,Digit_32 Int)
{
    //判断特殊情况
    if(Int==0)return Success;
    //判断是否超出空间
    if(src->MSB+1>(src->Len)<<5)
    {
        LastErrorCode=Error_Param_LargeNumber;
        return Fail;
    }
    //开始计算
    Digit_32 temp32=Int;
    Digit_64 temp64;
    int i;
    for(i=0;i<src->Len;i++)
    {
        temp64=(Digit_64)src->Data[i]+(Digit_64)temp32;
        src->Data[i]=(Digit_32)temp64;
        temp32=temp64>>32;
        if(temp32==0)break;
    }
    LnCulMSB(src);
    return Success;
}

int LnMinusInt(LN src,Digit_32 Int)
{
    //判断特殊情况
    if(Int==0)return Success;
    if(src->MSB==0)return Fail;
    if(src->Size==1)
    {
        if(src->Data[0]<Int)return Fail;
        src->Data-=Int;
        return Success;
    }
    //开始计算
    Digit_32 temp32=Int;
    Digit_64 temp64;
    int i,L=src->Size;
    for(i=0;i<L;i++)
    {
        if(src->Data[i]<temp32)
        {
            src->Data[i]=(Digit_32)((1ll<<32)+src->Data[i]-temp32);
            temp32=1;
        }
        else
        {
            src->Data[i]-=temp32;
            break;
        }
    }
    LnCulMSB(src);
    return Success;
}

int LnMultiplyInt(LN src,Digit_32 Int) 
{
    //判断特殊情况
    if(Int==0)
    {
        LnZero(src);
        return Success;
    }
    if(Int==1)return Success;
    //计算Int的MSB
    Digit_32 temp32=Int;
    int i;
    for(i=1;i<32;i++)
    {
        temp32>>=i;
        if(temp32==0)break;
    }
    //判断是否超出空间
    if(src->MSB+i>(src->Len)<<5)
    {
        LastErrorCode=Error_Param_LargeNumber;
        return Fail;
    }
    //乘法计算
    Digit_64 temp64;
    int L=src->Size;
    if(L+1<=src->Len)L++;
    for(i=0;i<L;i++)
    {
        temp64=(Digit_64)src->Data[i]*(Digit_64)Int+(Digit_64)temp32;
        src->Data[i]=(Digit_32)temp64;
        temp32=temp64>>32;
    }
    LnCulMSB(src);
    return Success;
}

int LnDivideInt(LN src,Digit_32 Int,Digit_32 *r)
{
    //判断特殊情况
    if(Int==0)return Fail;
    if(Int==1||src->MSB==0)
    {
        if(r!=NULL)*r=0;
        return Success;
    }
    //开始计算
    Digit_64 temp1=0,temp2=0;
    int i,L=src->Size;
    for(i=L-1;i>=0;i--)
    {
        temp1=temp2<<32;
        temp1|=(Digit_64)src->Data[i];
        src->Data[i]=temp1/Int;
        temp2=temp1%Int;
    }
    LnCulMSB(src);
    if(r!=NULL)*r=(Digit_32)temp2;
    return Success;
}

int LnPlus(LN src,LN dest)
{
    //判断特殊情况
    if(dest->MSB==0)return Success;
    if(src->MSB==0)return LnAssign(src,dest);
    //取src.MSB和dest.MSB中的最大值
    Digit_32 maxMSB=(src->MSB>dest->MSB?src->MSB:dest->MSB)+1;
    //判断是否超出空间
    if(maxMSB>src->Len<<5)
    {
        LastErrorCode=Error_Param_LargeNumber;
        return Fail;
    }
    //开始计算
    Digit_32 max=(maxMSB+31)>>5;
    Digit_32 ss=src->Size,ds=dest->Size;
    Digit_64 temp=0;
    int i;
    for(i=0;i<max;i++)
    {
        temp+=(Digit_64)(i<ss?src->Data[i]:0)+(Digit_64)(i<ds?dest->Data[i]:0);
        src->Data[i]=(Digit_32)temp;
        temp>>=32;
    }
    LnCulMSB(src);
    return Success;
}

int LnMinus(LN src,LN dest)
{
    //判断特殊情况
    //if(LnLess(src,dest)==TURE)return Fail;
    if(dest->MSB==0)return Success;
    //开始计算
    Digit_64 s1,s2,t,p=0;
    int i;
    for(i=0;i<src->Size;i++)
    {
        s1=src->Data[i];
        s2=dest->Data[i];
        if(s1<s2+p)
        {
            t=(4294967296)+s1-s2-p;
            p=1;
        }
        else
        {
            t=s1-s2-p;
            p=0;
        }
        src->Data[i]=(Digit_32)t;
    }
    LnCulMSB(src);
    return Success;
}

int LnMultiply(LN src,LN dest,LNT *LnTemp)
{
    //判断特殊情况
    if(dest->MSB==0)return LnZero(src);
    if(dest->MSB==1||src->MSB==0)return Success;
    if(src->MSB==1)return LnAssign(src,dest);
    //开始计算
    LN Temp0=&(LnTemp->TempMul0),Temp1=&(LnTemp->TempMul1);
    LnZero(Temp0);
    LnZero(Temp1);
    int i;
    for(i=0;i<dest->Size;i++)
    {
        if(dest->Data[i]==0)continue;
        if(LnAssign(Temp0,src)==Fail)return Fail;
        if(LnMultiplyInt(Temp0,dest->Data[i])==Fail)return Fail;
        if(LnMoveLeft(Temp0,i<<5)==Fail)return Fail;
        if(LnPlus(Temp1,Temp0)==Fail)return Fail;
    }
    if(LnAssign(src,Temp1)==Fail)return Fail;
    return Success;
}

int LnDivide(LN src,LN dest,LN result,LNT *LnTemp)
{
    LnZero(result);
    //判断特殊情况
    if(dest->MSB==0)return Fail;
    if(dest->MSB==1||src->MSB==0)
    {
        return Success;
    }
    if(LnLess(src,dest)==TURE)
    {
        return Success;
    }

    //开始计算
    Digit_32 a=src->MSB-dest->MSB;
    LN Temp=&(LnTemp->TempDiv0);
    while(a>=0)
    {
        if(LnAssign(Temp,dest)==Fail)return Fail;
        if(LnMoveLeft(Temp,a)==Fail)return Fail;
        if(LnGreaterEqual(src,Temp)==TURE)
        {
            if(LnMinus(src,Temp)==Fail)return Fail;
            LnSetBit(result,a,1);
            if(src->MSB<dest->MSB)break;
            a=src->MSB-dest->MSB;
        }
        else
        {
            if(a==0)break;
            else a--;
        }
    }
    return Success;
}

int LnModule(LN src,LN p,LN pt,LNT *LnTemp)
{
    //判断特殊情况
    if(p->MSB==0)return Fail;
    if(p->MSB==1||src->MSB==0)
    {
        return LnZero(src);
    }
    if(LnLess(src,p)==TURE)return Success;

    //开始计算
    LN Temp0=&(LnTemp->TempMod0);
    LN Temp1=&(LnTemp->TempMod1);
    LN Temp2=&(LnTemp->TempMod2);
    LN Temp3=&(LnTemp->TempMod3);

    if(LnAssign(Temp0,src)==Fail)return Fail;
    if(LnMoveRight(Temp0,p->MSB-1)==Fail)return Fail;
    if(LnMultiply(Temp0,pt,LnTemp)==Fail)return Fail;
    if(LnMoveRight(Temp0,p->MSB+1)==Fail)return Fail;
    if(LnMultiply(Temp0,p,LnTemp)==Fail)return Fail;

    if(LnAssignBit(Temp1,src,p->MSB+1)==Fail)return Fail;
    if(LnAssignBit(Temp2,Temp0,p->MSB+1)==Fail)return Fail;

    if(LnLess(Temp1,Temp2)==TURE)
    {
        if(LnPlus(Temp1,Temp3)==Fail)return Fail;
    }
    if(LnMinus(Temp1,Temp2)==Fail)return Fail;
    if(LnGreater(Temp1,p)==TURE)
    {
        if(LnMinus(Temp1,p)==Fail)return Fail;
    }
    if(LnAssign(src,Temp1)==Fail)return Fail;

    return Success;
}

int LnPlusMod(LN src,LN dest,LN p,LN pt,LNT *LnTemp)
{
    if(LnPlus(src,dest)==Fail)return Fail;
    if(LnModule(src,p,pt,LnTemp)==Fail)return Fail;
    return Success;
}

int LnMinusMod(LN src,LN dest,LN p,LN pt,LNT *LnTemp)
{
    if(LnGreaterEqual(src,dest)==TURE)
    {
        if(LnMinus(src,dest)==Fail)return Fail;
        if(LnModule(src,p,pt,LnTemp)==Fail)return Fail;
    }
    else
    {
        if(LnPlus(src,p)==Fail)return Fail;
        if(LnMinus(src,dest)==Fail)return Fail;
        if(LnModule(src,p,pt,LnTemp)==Fail)return Fail;
    }
    return Success;
}

int LnMultiplyMod(LN src,LN dest,LN p,LN pt,LNT *LnTemp)
{
    if(LnMultiply(src,dest,LnTemp)==Fail)return Fail;
    if(LnModule(src,p,pt,LnTemp)==Fail)return Fail;
    return Success;
}

int LnInverseElement(LN src,LN p,LN pt,LNT *LnTemp)
{
    //判断特殊情况
    if(src->MSB==0)return Fail;
    if(src->MSB==1)return Success;

    //初始化
    LN Temp0=&(LnTemp->TempInv0);
    LN Temp1=&(LnTemp->TempInv1);
    LN Temp2=&(LnTemp->TempInv2);

    LnZero(Temp0);
    LnSetBit(Temp0,0,1);
    if(LnAssign(Temp1,p)==Fail)return Fail;
    LnZero(Temp2);

    //开始计算
    while(1)
    {
        while(LnGetBit(src,0)==0)
        {
            LnMoveRightOne(src);
            if(LnGetBit(Temp0,0)==0)LnMoveRightOne(Temp0);
            else
            {
                if(LnPlus(Temp0,p)==Fail)return Fail;
                LnMoveRightOne(Temp0);
            }
        }
        while(LnGetBit(Temp1,0)==0)
        {
            LnMoveRightOne(Temp1);
            if(LnGetBit(Temp2,0)==0)LnMoveRightOne(Temp2);
            else
            {
                if(LnPlus(Temp2,p)==Fail)return Fail;
                LnMoveRightOne(Temp2);
            }
        }
        if(src->MSB==1||Temp1->MSB==1)break;
        if(LnGreater(src,Temp1)==TURE)
        {
            if(LnMinus(src,Temp1)==Fail)return Fail;
            if(LnMinusMod(Temp0,Temp2,p,pt,LnTemp)==Fail)return Fail;
        }
        else
        {
            if(LnMinus(Temp1,src)==Fail)return Fail;
            if(LnMinusMod(Temp2,Temp0,p,pt,LnTemp)==Fail)return Fail;
        }
        if(src->MSB==1||Temp1->MSB==1)break;
    }
    //输出结果
    if(src->MSB==1)
    {
        if(LnAssign(src,Temp0)==Fail)return Fail;
    }
    else
    {
        if(LnAssign(src,Temp2)==Fail)return Fail;
    }

    return Success;
}

int LnSetFromInts(LN src,int *Ints,Digit_32 Len)
{
    //判断是否超出空间
    if(src->Len<Len)
    {
        LastErrorCode=Error_Param_LargeNumber;
        return Fail;
    }
    //先清零，然后赋值数组
    if(src->MSB!=0)LnZero(src);
    int i,j=0;
    for(i=Len-1;i>=0;i--)src->Data[i]=Ints[j++];
    LnCulMSB(src);
    return Success;
}

int LnSetFromByte(LN src,Byte *Bytes,Digit_32 Len)
{
    //判断是否超出空间
    Digit_32 L=(Len+3)>>2;
    if(src->Len<L)
    {
        LastErrorCode=Error_Param_LargeNumber;
        return Fail;
    }
    //先清零，然后赋值
    if(src->MSB!=0)LnZero(src);
    int i,j=0;
    Byte *temp=(Byte*)src->Data;
    for(i=Len-1;i>=0;i--)temp[j++]=Bytes[i];
    LnCulMSB(src);
    return Success;
}

int LnSetFromHex(LN src,char *Hex,Digit_32 Len)
{
    Digit_32 L=(Len+7)>>3;
    if(src->Len<L)
    {
        LastErrorCode=Error_Param_LargeNumber;
        return Fail;
    }
    if(src->MSB!=0)LnZero(src);
    int i,j=0,k=1;
    Byte *temp=(Byte*)src->Data;
    for(i=Len-1;i>=0;i--)
    {
        if(k)
        {
            temp[j]|=CharToNum(Hex[i]);
            k=0;
        }
        else
        {
            temp[j++]|=CharToNum(Hex[i])<<4;
            k=1;
        }
    }
    LnCulMSB(src);
    return Success;
}

int LnSetFromDec(LN src,char *Dec,Digit_32 Len)
{
    LnZero(src);
    Byte *temp=Dec;
    Digit_32 s;
    int i;
    for(i=0;i<Len;i+=9)
    {
        if(i+9<=Len)
        {
           if(LnMultiplyInt(src,1000000000)!=Success)return Fail;
           if(LnPlusInt(src,TextToNumber(temp,9))!=Success)return Fail;
           temp+=9;
        }
        else
        {
            if(LnMultiplyInt(src,TenPower(Len-i))!=Success)return Fail;
            if(LnPlusInt(src,TextToNumber(temp,Len-i))!=Success)return Fail;
        }
    }
    LnCulMSB(src);
    return Success;
}


int LnOutputByte(LN src,Byte *Buf,int Len)
{
    Byte* Temp=(Byte*)src->Data;
    Digit_32 L=(src->MSB+7)>>3;
    L--;
    int i;
    for(i=0;i<Len;i++)
    {
        Buf[i]=Temp[L];
        if(L==0)break;
        else L--;
    }
    return i+1;
}

int LnOutputText(LN src,char *Buf,int Len)
{
    if(Len<=0)return 0;
    Byte *Temp=(Byte*)src->Data;
    Digit_32 L=(src->MSB+7)>>3;
    if(L==0)return 0;
    L--;
    int i;
    for(i=0;i<Len;i++)
    {
        if(i&1)
        {
            Buf[i]=Base16[Temp[L]&15];
            if(L==0)break;
            else L--;
        }
        else
        {
            Buf[i]=Base16[Temp[L]>>4];
        }
    }
    return i+1;
}

//----------------------------------------

int ElCheck(Entropy ELib)
{
    if(ELib==NULL)return Fail;
    if(ELib->Lib==NULL)
    {
        LastErrorCode=Error_Entropy_Uninit;
        return Fail;
    }
    return Success;
}

int ElFree(Entropy ELib)
{
    if(ElCheck(ELib)==Fail)return Fail;
    free(ELib->Lib);
    free(ELib);
    return Success;
}

Entropy ElInit(int MaxSize)
{
    if(MaxSize<=0)
    {
        LastErrorCode=Error_Entropy_MaxSize;
        return NULL;
    }

    Entropy Temp=(Entropy)malloc(sizeof(struct Entropy));
    if(Temp==NULL)
    {
        LastErrorCode=Error_MallocFail;
        return NULL;
    }

    Byte *temp=(Byte*)malloc(MaxSize);
    if(temp==NULL)
    {
        free(Temp);
        LastErrorCode=Error_MallocFail;
        return NULL;
    }
    int i;
    for(i=0;i<MaxSize;i++)temp[i]=0;

    Temp->Lib=temp;
    Temp->Size=0;
    Temp->MaxSize=MaxSize;

    return Temp;
}

int ElEmpty(Entropy ELib)
{
    if(ElCheck(ELib)==Fail)return Fail;
    int i,L=ELib->MaxSize;
    for(i=0;i<L;i++)ELib->Lib[i]=0;
    ELib->Size=0;
    return Success;
}

int ElInput(Entropy ELib,Byte *Data,int Len,Bool Hash)
{
    if(ElCheck(ELib)==Fail)return Fail;
    if(Data==NULL)
    {
        LastErrorCode=Error_Entropy_Data;
        return Fail;
    }
    if(Len<=0)
    {
        LastErrorCode=Error_Entropy_Len;
        return Fail;
    }

    Byte *Message,Result[32];
    int L=Len+12,i,j=0,k=0;
    time_t t=time(NULL);
    clock_t c=clock();

    Message=(Byte*)malloc(L);
    if(Message==NULL)
    {
        LastErrorCode=Error_MallocFail;
        return Fail;
    }

    for(i=0;i<8;i++)
    {
        Message[i]=(Byte)t;
        t>>8;
    }
    for(i=8;i<12;i++)
    {
        Message[i]=(Byte)c;
        c>>8;
    }
    for(i=12;i<L;i++)Message[i]=Data[j++];

    if(Hash==0)SHA256T(Message,L,Result);
    else SM3T(Message,L,Result);

    free(Message);

    if(ELib->Size==ELib->MaxSize)
    {
        for(i=0;i<ELib->Size;i++)
        {
            if(i+32>=ELib->MaxSize)ELib->Lib[i]=0;
            else ELib->Lib[i]=ELib->Lib[i+32];
        }
        ELib->Size-=32;
    }

    for(i=0;i<32;i++)
    {
        if(ELib->Size+1>ELib->MaxSize)break;
        ELib->Lib[ELib->Size++]=Result[i];
    }

    return Success;
}

int ElRandom(Entropy ELib,LN dest,Digit_32 Len)
{
    if(ElCheck(ELib)==Fail)return Fail;
    if(Len>ELib->Size)
    {
        LastErrorCode=Error_Entropy_Lack;
        return Fail;
    }
    if(LnSetFromByte(dest,ELib->Lib,Len)==Fail)return Fail;

    int i;
    for(i=0;i<ELib->Size;i++)
    {
        if(i+Len>=ELib->MaxSize)ELib->Lib[i]=0;
        else ELib->Lib[i]=ELib->Lib[i+Len];
    }
    ELib->Size-=Len;
    return Success;
}

int ElGetSize(Entropy ELib)
{
    if(ElCheck(ELib)==Fail)return Fail;
    return ELib->Size;
}

int ElPrint(Entropy ELib)
{
    int i;
    printf("\nEntropyLib:\n");
    for(i=0;i<ELib->Size;i++)
    {
        printf("%02X",ELib->Lib[i]);
        if(((i+1)&3)==0)putchar(',');
        if(((i+1)&31)==0)putchar('\n');
    }
    return Success;
}

//----------------------------------------

int PointAssign(Point src,Point dest)
{
    if(LnAssign(&src->X,&dest->X)==Fail)return Fail;
    if(LnAssign(&src->Y,&dest->Y)==Fail)return Fail;
    return Success;
}

int PointToJPoint(JPoint src,Point dest)
{
    if(LnAssign(&src->X,&dest->X)==Fail)return Fail;
    if(LnAssign(&src->Y,&dest->Y)==Fail)return Fail;
    LnZero(&src->Z);
    LnSetBit(&src->Z,0,1);
    return Success;
}

int PointIsZero(Point src)
{
    if(src->X.MSB==0&&src->Y.MSB==0)return TURE;
    else return FALSE;
}

//----------------------------------------

int JPointIsZero(JPoint src)
{
    if(src->Z.MSB==0)return TURE;
    return FALSE;
}

int JPointAssign(JPoint src,JPoint dest)
{
    if(LnAssign(&src->X,&dest->X)==Fail)return Fail;
    if(LnAssign(&src->Y,&dest->Y)==Fail)return Fail;
    if(LnAssign(&src->Z,&dest->Z)==Fail)return Fail;
    return Success;
}

int JPointToPoint(Point src,JPoint dest,CurveT *C,LN p,LN pt,LNT *LnTemp)
{
    if(LnAssign(&C->Temp0,&dest->Z)==Fail)return Fail;                      //s1=z1
    if(LnMultiplyMod(&C->Temp0,&dest->Z,p,pt,LnTemp)==Fail)return Fail;     //s1=z1^2
    if(LnAssign(&C->Temp1,&C->Temp0)==Fail)return Fail;                     //s2=s1=z1^2
    if(LnInverseElement(&C->Temp1,p,pt,LnTemp)==Fail)return Fail;           //s2=s2^-1
    if(LnAssign(&src->X,&dest->X)==Fail)return Fail;                        //x2=x1
    if(LnMultiplyMod(&src->X,&C->Temp1,p,pt,LnTemp)==Fail)return Fail;      //x2=x1*s2
    if(LnMultiplyMod(&C->Temp0,&dest->Z,p,pt,LnTemp)==Fail)return Fail;     //s1=z1^3
    if(LnInverseElement(&C->Temp0,p,pt,LnTemp)==Fail)return Fail;           //s1=s1^-1
    if(LnAssign(&src->Y,&dest->Y)==Fail)return Fail;                        //y2=y1
    if(LnMultiplyMod(&src->Y,&C->Temp0,p,pt,LnTemp)==Fail)return Fail;      //y2=y1*s1
    return Success;
}

int JPointPlus(JPoint src,JPoint dest,CurveT *C,LN p,LN pt,LNT *LnTemp)
{
    if(JPointIsZero(dest)==TURE)return Success;
    if(JPointIsZero(src)==TURE)
    {
        if(JPointAssign(src,dest)==Fail)return Fail;
        return Success;
    }

    if(LnAssign(&C->Temp0,&dest->Z)==Fail)return Fail;                      //s1=z2
    if(LnMultiplyMod(&C->Temp0,&dest->Z,p,pt,LnTemp)==Fail)return Fail;     //s1=z2^2

    if(LnAssign(&C->Temp1,&src->Z)==Fail)return Fail;                       //s2=z1
    if(LnMultiplyMod(&C->Temp1,&src->Z,p,pt,LnTemp)==Fail)return Fail;      //s2=z1^2

    if(LnAssign(&C->Temp2,&src->X)==Fail)return Fail;                       //s3=x1
    if(LnMultiplyMod(&C->Temp2,&C->Temp0,p,pt,LnTemp)==Fail)return Fail;    //s3=x1*z2^2

    if(LnAssign(&C->Temp3,&dest->X)==Fail)return Fail;                      //s4=x2
    if(LnMultiplyMod(&C->Temp3,&C->Temp1,p,pt,LnTemp)==Fail)return Fail;    //s4=x2*z1^2

    if(LnAssign(&C->Temp4,&C->Temp2)==Fail)return Fail;                     //s5=s3
    if(LnMinusMod(&C->Temp4,&C->Temp3,p,pt,LnTemp)==Fail)return Fail;       //s5=s3-s4

    if(LnAssign(&C->Temp5,&C->Temp2)==Fail)return Fail;                     //s6=s3
    if(LnPlusMod(&C->Temp5,&C->Temp3,p,pt,LnTemp)==Fail)return Fail;        //s6=s3+s4

    if(LnMultiplyMod(&C->Temp0,&dest->Z,p,pt,LnTemp)==Fail)return Fail;     //s1=z2^3
    if(LnMultiplyMod(&C->Temp0,&src->Y,p,pt,LnTemp)==Fail)return Fail;      //s1=y1*z2^3

    if(LnMultiplyMod(&C->Temp1,&src->Z,p,pt,LnTemp)==Fail)return Fail;      //s2=z1^3
    if(LnMultiplyMod(&C->Temp1,&dest->Y,p,pt,LnTemp)==Fail)return Fail;     //s2=y2*z1^3

    if(LnAssign(&C->Temp3,&C->Temp0)==Fail)return Fail;                     //s4=s1
    if(LnMinusMod(&C->Temp3,&C->Temp1,p,pt,LnTemp)==Fail)return Fail;       //s4=s1-s2

    if(LnAssign(&src->X,&C->Temp3)==Fail)return Fail;                       //x3=s4
    if(LnMultiplyMod(&src->X,&C->Temp3,p,pt,LnTemp)==Fail)return Fail;      //x3=s4^2

    //自此，s2为临时大数

    if(LnAssign(&C->Temp1,&C->Temp5)==Fail)return Fail;                     //s2=s6
    if(LnMultiplyMod(&C->Temp1,&C->Temp4,p,pt,LnTemp)==Fail)return Fail;    //s2=s6*s5
    if(LnMultiplyMod(&C->Temp1,&C->Temp4,p,pt,LnTemp)==Fail)return Fail;    //s2=s6*s5^2

    if(LnMinusMod(&src->X,&C->Temp1,p,pt,LnTemp)==Fail)return Fail;         //x3=s4^2-s6*s5^2

    if(LnAssign(&C->Temp1,&C->Temp4)==Fail)return Fail;                     //s2=s5
    if(LnMultiplyMod(&C->Temp1,&C->Temp4,p,pt,LnTemp)==Fail)return Fail;    //s2=s5^2

    if(LnAssign(&src->Y,&C->Temp2)==Fail)return Fail;                       //y3=s3
    if(LnMultiplyMod(&src->Y,&C->Temp1,p,pt,LnTemp)==Fail)return Fail;      //y3=s3*s5^2
    if(LnMinusMod(&src->Y,&src->X,p,pt,LnTemp)==Fail)return Fail;           //y3=s3*s5^2-x3

    if(LnMultiplyMod(&C->Temp1,&C->Temp4,p,pt,LnTemp)==Fail)return Fail;    //s2=s5^3
    if(LnMultiplyMod(&C->Temp1,&C->Temp0,p,pt,LnTemp)==Fail)return Fail;    //s2=s1*s5^3

    if(LnMultiplyMod(&src->Y,&C->Temp3,p,pt,LnTemp)==Fail)return Fail;      //y3=s4*(s3*s5^2-x3)
    if(LnMinusMod(&src->Y,&C->Temp1,p,pt,LnTemp)==Fail)return Fail;         //y3=s4*(s3*s5^2-x3)-s1*s5^3

    //此时z3=z1
    if(LnMultiplyMod(&src->Z,&dest->Z,p,pt,LnTemp)==Fail)return Fail;       //z3=z1*z2
    if(LnMultiplyMod(&src->Z,&C->Temp4,p,pt,LnTemp)==Fail)return Fail;      //z3=z1*z2*s5

    return Success;
}

int JPointDouble(JPoint src,CurveT *C,LN a,LN p,LN pt,LNT *LnTemp)
{
    if(JPointIsZero(src)==TURE)return Success;

    if(LnAssign(&C->Temp0,&src->X)==Fail)return Fail;                  //s1=x1
    if(LnMultiplyInt(&C->Temp0,3)==Fail)return Fail;                  //s1=3*x1
    if(LnMultiplyMod(&C->Temp0,&src->X,p,pt,LnTemp)==Fail)return Fail;     //s1=3*x1^2

    if(LnAssign(&C->Temp1,&src->Z)==Fail)return Fail;                  //s2=z1
    if(LnMultiplyMod(&C->Temp1,&src->Z,p,pt,LnTemp)==Fail)return Fail;     //s2=z1^2

    if(LnAssign(&C->Temp3,&C->Temp1)==Fail)return Fail;                 //s4=z1^2
    if(LnMultiplyMod(&C->Temp3,&C->Temp1,p,pt,LnTemp)==Fail)return Fail;    //s4=z1^4
    if(LnMultiplyMod(&C->Temp3,a,p,pt,LnTemp)==Fail)return Fail;    //s4=a*z1^4

    if(LnPlusMod(&C->Temp0,&C->Temp3,p,pt,LnTemp)==Fail)return Fail;        //s1=3*x1^2+a*z1^4

    if(LnAssign(&C->Temp3,&src->Y)==Fail)return Fail;                  //s4=y1
    if(LnMultiplyMod(&C->Temp3,&src->Y,p,pt,LnTemp)==Fail)return Fail;     //s4=y1^2

    if(LnAssign(&C->Temp1,&src->X)==Fail)return Fail;                  //s2=x1
    if(LnMoveLeft(&C->Temp1,2)==Fail)return Fail;                     //s2=4*x1
    if(LnMultiplyMod(&C->Temp1,&C->Temp3,p,pt,LnTemp)==Fail)return Fail;    //s2=4*x1*y1^2

    if(LnAssign(&C->Temp2,&C->Temp3)==Fail)return Fail;                 //s3=y1^2
    if(LnMoveLeft(&C->Temp2,3)==Fail)return Fail;                     //s3=8*y1^2
    if(LnMultiplyMod(&C->Temp2,&C->Temp3,p,pt,LnTemp)==Fail)return Fail;    //s3=8*y1^4

    if(LnAssign(&C->Temp3,&C->Temp1)==Fail)return Fail;                 //s4=s2
    if(LnMoveLeft(&C->Temp3,1)==Fail)return Fail;
    if(LnModule(&C->Temp3,p,pt,LnTemp)==Fail)return Fail;                 //s4=2*s2

    if(LnAssign(&src->X,&C->Temp0)==Fail)return Fail;                  //x3=s1
    if(LnMultiplyMod(&src->X,&C->Temp0,p,pt,LnTemp)==Fail)return Fail;     //x3=s1^2
    if(LnMinusMod(&src->X,&C->Temp3,p,pt,LnTemp)==Fail)return Fail;        //x3=s1^2-2*s2

    //此时z3=z1
    if(LnMoveLeft(&src->Z,1)==Fail)return Fail;                      //z3=2*z1
    if(LnMultiplyMod(&src->Z,&src->Y,p,pt,LnTemp)==Fail)return Fail;      //z3=2*y1*z1

    if(LnAssign(&src->Y,&C->Temp1)==Fail)return Fail;                  //y3=s2
    if(LnMinusMod(&src->Y,&src->X,p,pt,LnTemp)==Fail)return Fail;         //y3=s2-x3
    if(LnMultiplyMod(&src->Y,&C->Temp0,p,pt,LnTemp)==Fail)return Fail;     //y3=s1*(s2-x3)
    if(LnMinusMod(&src->Y,&C->Temp2,p,pt,LnTemp)==Fail)return Fail;        //y3=s1*(s2-x3)-s3

    return Success;
}

int JPointMultiplyBinary(JPoint src,LN Number,CurveT *C,LN a,LN p,LN pt,LNT *LnTemp)
{
    Digit_32 i=0,High=Number->MSB;

    if(JPointAssign(&C->TempJ0,src)==Fail)return Fail;
    LnZero(&src->Z);

    while(i<=High)
    {
        if(LnGetBit(Number,i)==0)
        {
            if(JPointDouble(&C->TempJ0,C,a,p,pt,LnTemp)==Fail)return Fail;
        }
        else
        {
            if(JPointPlus(src,&C->TempJ0,C,p,pt,LnTemp)==Fail)return Fail;
            if(JPointDouble(&C->TempJ0,C,a,p,pt,LnTemp)==Fail)return Fail;
        }
        i++;
    }

    return Success;
}

//----------------------------------------

int PointMul(Point src,LN Number,Point dest,CurveT *C,LN a,LN p,LN pt,LNT *LnTemp)
{
    if(PointIsZero(src)==TURE)
    {
        LastErrorCode=Error_ECC_ZeroPoint;
        return Fail;
    }

    if(PointToJPoint(&C->TempJ1,src)==Fail)return Fail;

    if(JPointMultiplyBinary(&C->TempJ1,Number,C,a,p,pt,LnTemp)==Fail)return Fail;

    if(JPointIsZero(&C->TempJ1)==TURE)
    {
        LastErrorCode=Error_ECC_ZeroPoint;
        return Fail;
    }

    if(JPointToPoint(dest,&C->TempJ1,C,p,pt,LnTemp)==Fail)return Fail;

    return Success;
}

//----------------------------------------

void LnInit(LN src,Digit_32 Len,Digit_32 *pointer)
{
    src->Size=1;
    src->MSB=0;
    src->Len=Len;
    src->Data=pointer;
}

Digit_32* CPInit(CurveParam *src,Digit_32 *pointer,Digit_32 Len)
{
    Digit_32 *temp=pointer;
    LnInit(&src->P,Len,temp);
    temp+=Len;
    LnInit(&src->A,Len,temp);
    temp+=Len;
    LnInit(&src->B,Len,temp);
    temp+=Len;
    LnInit(&src->N,Len,temp);
    temp+=Len;
    LnInit(&src->D,Len,temp);
    temp+=Len;
    LnInit(&src->PT,Len,temp);
    temp+=Len;
    LnInit(&src->NT,Len,temp);
    temp+=Len;
    LnInit(&src->G.X,Len,temp);
    temp+=Len;
    LnInit(&src->G.Y,Len,temp);
    temp+=Len;
    LnInit(&src->Public.X,Len,temp);
    temp+=Len;
    LnInit(&src->Public.Y,Len,temp);
    temp+=Len;
    return temp;
}

Digit_32* LNTInit(LNT *src,Digit_32 *pointer,int Len)
{
    Digit_32 *temp=pointer;
    LnInit(&src->TempMul0,Len,temp);
    temp+=Len;
    LnInit(&src->TempMul1,Len,temp);
    temp+=Len;
    LnInit(&src->TempDiv0,Len,temp);
    temp+=Len;
    LnInit(&src->TempMod0,Len,temp);
    temp+=Len;
    LnInit(&src->TempMod1,Len,temp);
    temp+=Len;
    LnInit(&src->TempMod2,Len,temp);
    temp+=Len;
    LnInit(&src->TempMod3,Len,temp);
    temp+=Len;
    LnInit(&src->TempInv0,Len,temp);
    temp+=Len;
    LnInit(&src->TempInv1,Len,temp);
    temp+=Len;
    LnInit(&src->TempInv2,Len,temp);
    temp+=Len;
    LnInit(&src->Temp,Len,temp);
    temp+=Len;
    return temp;
}

Digit_32* CTInit(CurveT *src,Digit_32 *pointer,int Len)
{
    Digit_32 *temp=pointer;
    LnInit(&src->Temp0,Len,temp);
    temp+=Len;
    LnInit(&src->Temp1,Len,temp);
    temp+=Len;
    LnInit(&src->Temp2,Len,temp);
    temp+=Len;
    LnInit(&src->Temp3,Len,temp);
    temp+=Len;
    LnInit(&src->Temp4,Len,temp);
    temp+=Len;
    LnInit(&src->Temp5,Len,temp);
    temp+=Len;
    LnInit(&src->TempP0.X,Len,temp);
    temp+=Len;
    LnInit(&src->TempP0.Y,Len,temp);
    temp+=Len;
    LnInit(&src->TempP1.X,Len,temp);
    temp+=Len;
    LnInit(&src->TempP1.Y,Len,temp);
    temp+=Len;
    LnInit(&src->TempJ0.X,Len,temp);
    temp+=Len;
    LnInit(&src->TempJ0.Y,Len,temp);
    temp+=Len;
    LnInit(&src->TempJ0.Z,Len,temp);
    temp+=Len;
    LnInit(&src->TempJ1.X,Len,temp);
    temp+=Len;
    LnInit(&src->TempJ1.Y,Len,temp);
    temp+=Len;
    LnInit(&src->TempJ1.Z,Len,temp);
    temp+=Len;
    return temp;
}

void PTNTInit(CurveContext src)
{
    LnZero(&src->LNTemp.TempMod3);
    LnSetBit(&src->LNTemp.TempMod3,(src->Bit<<1),1);
    LnDivide(&src->LNTemp.TempMod3,&src->Param.P,&src->Param.PT,&src->LNTemp);

    LnZero(&src->LNTemp.TempMod3);
    LnSetBit(&src->LNTemp.TempMod3,(src->Bit<<1),1);
    LnDivide(&src->LNTemp.TempMod3,&src->Param.N,&src->Param.NT,&src->LNTemp);

    LnZero(&src->LNTemp.TempMod3);
    LnSetBit(&src->LNTemp.TempMod3,src->Bit+1,1);
}

int EccParamInit(CurveContext src,int CurveID)
{
    if(CurveID==ECC_ansip192k1)
    {
        char P[48]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37";
        char A[2]="00";
        char B[2]="03";
        char X[48]="DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D";
        char Y[48]="9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D";
        char N[48]="FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D";
        if(LnSetFromHex(&src->Param.P,P,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,2)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,2)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,48)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_ansip224r1)
    {
        char P[56]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001";
        char A[56]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE";
        char B[56]="B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4";
        char X[56]="B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21";
        char Y[56]="BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34";
        char N[56]="FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D";
        if(LnSetFromHex(&src->Param.P,P,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,56)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_ansip256k1)
    {
        char P[64]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
        char A[2]="00";
        char B[2]="07";
        char X[64]="79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        char Y[64]="483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
        char N[64]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        if(LnSetFromHex(&src->Param.P,P,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,2)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,2)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,64)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_ansip384r1)
    {
        char P[96]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF";
        char A[96]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC";
        char B[96]="B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF";
        char X[96]="AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7";
        char Y[96]="3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F";
        char N[96]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973";
        if(LnSetFromHex(&src->Param.P,P,96)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,96)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,96)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,96)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,96)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,96)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_brainpoolP224r1)
    {
        char P[56]="D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF";
        char A[56]="68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43";
        char B[56]="2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B";
        char X[56]="0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D";
        char Y[56]="58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD";
        char N[56]="D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F";
        if(LnSetFromHex(&src->Param.P,P,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,56)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_brainpoolP224t1)
    {
        char P[56]="D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF";
        char A[56]="D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FC";
        char B[56]="4B337D934104CD7BEF271BF60CED1ED20DA14C08B3BB64F18A60888D";
        char X[56]="6AB1E344CE25FF3896424E7FFE14762ECB49F8928AC0C76029B4D580";
        char Y[56]="0374E9F5143E568CD23F3F4D7C0D4B1E41C8CC0D1C6ABD5F1A46DB4C";
        char N[56]="D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F";
        if(LnSetFromHex(&src->Param.P,P,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,56)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,56)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_gost256)
    {
        char P[64]="8000000000000000000000000000000000000000000000000000000000000431";
        char A[64]="07";
        char B[64]="5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E";
        char X[64]="02";
        char Y[64]="08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8";
        char N[64]="8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3";
        if(LnSetFromHex(&src->Param.P,P,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,2)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,2)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,64)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_numsp256d1)
    {
        char P[64]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43";
        char A[64]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40";
        char B[6]="025581";
        char X[2]="01";
        char Y[64]="696F1853C1E466D7FC82C96CCEEEDD6BD02C2F9375894EC10BF46306C2B56C77";
        char N[64]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE43C8275EA265C6020AB20294751A825";
        if(LnSetFromHex(&src->Param.P,P,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,6)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,2)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,64)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_numsp384d1)
    {
        char P[96]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC3";
        char A[96]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC0";
        char B[96]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77BB";
        char X[2]="02";
        char Y[96]="3C9F82CB4B87B4DC71E763E0663E5DBD8034ED422F04F82673330DC58D15FFA2B4A3D0BAD5D30F865BCBBF503EA66F43";
        char N[96]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD61EAF1EEB5D6881BEDA9D3D4C37E27A604D81F67B0E61B9";
        if(LnSetFromHex(&src->Param.P,P,96)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,96)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,96)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,2)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,96)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,96)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_numsp512d1)
    {
        char P[128]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7";
        char A[128]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4";
        char B[6]="01D99B";
        char X[2]="02";
        char Y[128]="1C282EB23327F9711952C250EA61AD53FCC13031CF6DD336E0B9328433AFBDD8CC5A1C1F0C716FDC724DDE537C2B0ADB00BB3D08DC83755B205CC30D7F83CF28";
        char N[128]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5B3CA4FB94E7831B4FC258ED97D0BDC63B568B36607CD243CE153F390433555D";
        if(LnSetFromHex(&src->Param.P,P,128)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,128)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,6)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,2)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,128)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,128)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_prime192v1)
    {
        char P[48]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF";
        char A[48]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC";
        char B[48]="64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1";
        char X[48]="188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012";
        char Y[48]="07192B95FFC8DA78631011ED6B24CDD573F977A11E794811";
        char N[48]="FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831";
        if(LnSetFromHex(&src->Param.P,P,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,48)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_prime192v2)
    {
        char P[48]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF";
        char A[48]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC";
        char B[48]="CC22D6DFB95C6B25E49C0D6364A4E5980C393AA21668D953";
        char X[48]="EEA2BAE7E1497842F2DE7769CFE9C989C072AD696F48034A";
        char Y[48]="6574D11D69B6EC7A672BB82A083DF2F2B0847DE970B2DE15";
        char N[48]="FFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC80418648D8DD31";
        if(LnSetFromHex(&src->Param.P,P,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,48)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_prime192v3)
    {
        char P[48]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF";
        char A[48]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC";
        char B[48]="22123DC2395A05CAA7423DAECCC94760A7D462256BD56916";
        char X[48]="7D29778100C65A1DA1783716588DCE2B8B4AEE8E228F1896";
        char Y[48]="38A90F22637337334B49DCB66A6DC8F9978ACA7648A943B0";
        char N[48]="FFFFFFFFFFFFFFFFFFFFFFFF7A62D031C83F4294F640EC13";
        if(LnSetFromHex(&src->Param.P,P,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,48)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,48)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_prime256v1)
    {
        char P[64]="FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
        char A[64]="FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
        char B[64]="5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
        char X[64]="6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
        char Y[64]="4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
        char N[64]="FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
        if(LnSetFromHex(&src->Param.P,P,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,64)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_secp128r1)
    {
        char P[32]="FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF";
        char A[32]="FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC";
        char B[32]="E87579C11079F43DD824993C2CEE5ED3";
        char X[32]="161FF7528B899B2D0C28607CA52C5B86";
        char Y[32]="CF5AC8395BAFEB13C02DA292DDED7A83";
        char N[32]="FFFFFFFE0000000075A30D1B9038A115";
        if(LnSetFromHex(&src->Param.P,P,32)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,32)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,32)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,32)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,32)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,32)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_sm2p256e)
    {
        char P[64]="8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
        char A[64]="787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
        char B[64]="63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
        char X[64]="421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
        char Y[64]="0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
        char N[64]="8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
        if(LnSetFromHex(&src->Param.P,P,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,64)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }
    if(CurveID==ECC_sm2p256)
    {
        char P[64]="FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
        char A[64]="FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
        char B[64]="28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
        char X[64]="32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
        char Y[64]="BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
        char N[64]="FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
        if(LnSetFromHex(&src->Param.P,P,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.A,A,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.B,B,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.X,X,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.G.Y,Y,64)==Fail)return Fail;
        if(LnSetFromHex(&src->Param.N,N,64)==Fail)return Fail;

        PTNTInit(src);

        return Success;
    }

    LastErrorCode=Error_ECC_CurveID;
    return Fail;
}

CurveContext EccInitT(int CurveID)
{
    Digit_32 Bit=((CurveID%10000)/10);
    Digit_32 LL=((Bit<<1)+32)>>5;
    Digit_32 Len=LL<<3;
    

    CurveContext Temp=(CurveContext)malloc(sizeof(struct CurveContext));
    if(Temp==NULL)
    {
        LastErrorCode=Error_MallocFail;
        return NULL;
    }

    Temp->Bit=Bit;
    Temp->ID=CurveID;
    Temp->IsCulPublic=Temp->IsInputSign=0;
    Temp->CipherText=Temp->PlainText=Temp->PlainText=NULL;
    Temp->CipherTextLen=Temp->PlainTextLen=0;

    Digit_32 *temp=(Digit_32*)malloc(38*Len);
    if(temp==NULL)
    {
        free(Temp);
        LastErrorCode=Error_MallocFail;
        return NULL;
    }
    int j,L=(38*Len)>>2;
    for(j=0;j<L;j++)temp[j]=0;

    Temp->FreePointer=temp;
    temp=CPInit(&Temp->Param,temp,LL);
    temp=LNTInit(&Temp->LNTemp,temp,LL);
    temp=CTInit(&Temp->CurveTemp,temp,LL);
    if((temp-38*LL)!=Temp->FreePointer)
    {
        free(Temp->FreePointer);
        free(Temp);
        LastErrorCode=Error_ECC_Unknown;
        return NULL;
    }

    if(EccParamInit(Temp,CurveID)==Fail)
    {
        free(Temp->FreePointer);
        free(Temp);
        return NULL;
    }

    return Temp;
}

int EccFreeCacheT(CurveContext src)
{
    if(src!=NULL)
    {
        if(src->CipherText!=NULL)free(src->CipherText);
        if(src->PlainText!=NULL)free(src->PlainText);
        if(src->DigestText!=NULL)free(src->DigestText);
        src->CipherText=NULL;
        src->PlainText=NULL;
        src->DigestText=NULL;
    }
    return Success;
}

int EccFreeT(CurveContext src)
{
    if(src!=NULL)
    {
        EccFreeCacheT(src);

        if(src->FreePointer!=NULL)free(src->FreePointer);
        free(src);
    }
    return Success;
}

int EccPkgefT(CurveContext src,Entropy ELib)
{
    if(src==NULL)return Fail;
    Digit_32 L=src->Bit>>3;
    if((src->Bit&7)==0)
    {
        return ElRandom(ELib,&src->Param.D,L);
    }
    else
    {
        if(ElRandom(ELib,&src->LNTemp.Temp,(int)(L+1))==Fail)return Fail;
        return LnAssignBit(&src->Param.D,&src->LNTemp.Temp,src->Bit);
    }
}

int EccInputPriKeyT(CurveContext src,char *Key,int Len)
{
    if(src==NULL)return Fail;

    if(Key==NULL)
    {
        LastErrorCode=Error_ECC_Key;
        return Fail;
    }

    if((src->Bit&3)==0)
    {
        if(Len!=(src->Bit>>2))
        {
            LastErrorCode=Error_ECC_Len;
            return Fail;
        }
        return LnSetFromHex(&src->Param.D,Key,Len);
    }
    else
    {
        if(Len!=((src->Bit+3)>>2))
        {
            LastErrorCode=Error_ECC_Len;
            return Fail;
        }
        if(LnSetFromHex(&src->LNTemp.Temp,Key,Len)==Fail)return Fail;
        return LnAssignBit(&src->Param.D,&src->LNTemp.Temp,src->Bit);
    }
}

int EccInputPubKeyT(CurveContext src,char *Key,int Len)
{
    if(src==NULL)return Fail;

    if(Key==NULL)
    {
        LastErrorCode=Error_ECC_Key;
        return Fail;
    }
    Digit_32 L=Len>>1;
    if(src->Bit&3==0)
    {
        if(Len!=(src->Bit>>2))
        {
            LastErrorCode=Error_ECC_Len;
            return Fail;
        }
        if(LnSetFromHex(&src->Param.Public.X,Key,L)==Fail)return Fail;
        Key+=L;
        if(LnSetFromHex(&src->Param.Public.Y,Key,L)==Fail)
        {
            src->IsCulPublic=0;
            return Fail;
        }
        else
        {
            src->IsCulPublic=1;
            return Success;
        }
    }
    else
    {
        Digit_32 LL=(src->Bit+3)>>2;
        if(Len!=(LL<<1))
        {
            LastErrorCode=Error_ECC_Len;
            return Fail;
        }
        if(LnSetFromHex(&src->LNTemp.Temp,Key,L)==Fail)return Fail;
        if(LnAssignBit(&src->Param.Public.X,&src->LNTemp.Temp,src->Bit)==Fail)return Fail;
        Key+=L;
        if(LnSetFromHex(&src->LNTemp.Temp,Key,L)==Fail)return Fail;
        if(LnAssignBit(&src->Param.Public.Y,&src->LNTemp.Temp,src->Bit)==Fail)
        {
            src->IsCulPublic=0;
            return Fail;
        }
        else
        {
            src->IsCulPublic=1;
            return Success;
        }
    }
}

int EccCulPKeyT(CurveContext src)
{
    if(src==NULL)return Fail;
    if(src->Param.D.MSB==0)
    {
        LastErrorCode=Error_ECC_Private;
        return Fail;
    }
    if(PointMul(&src->Param.G,&src->Param.D,&src->Param.Public,&src->CurveTemp,&src->Param.A,&src->Param.P,&src->Param.PT,&src->LNTemp)==Fail)return Fail;
    else
    {
        src->IsCulPublic=1;
        return Success;
    }
}

int EccOutputPriKeyT(CurveContext src,Byte *Buf,int Len)
{
    if(src==NULL)return Fail;
    if(src->Param.D.MSB==0)
    {
        LastErrorCode=Error_ECC_Private;
        return Fail;
    }

    if(Buf==NULL)
    {
        LastErrorCode=Error_ECC_Buf;
    }
    if(Len<=0)
    {
        LastErrorCode=Error_ECC_Len;
        return Fail;
    }
    return LnOutputText(&src->Param.D,Buf,Len);
}

int EccOutputPubKeyT(CurveContext src,Byte *Buf,int Len)
{
    if(src==NULL)return Fail;
    if(Buf==NULL)
    {
        LastErrorCode=Error_ECC_Buf;
    }
    if(Len<=0)
    {
        LastErrorCode=Error_ECC_Len;
        return Fail;
    }
    int i=LnOutputText(&src->Param.Public.X,Buf,Len);
    int j=LnOutputText(&src->Param.Public.Y,Buf+i,Len-i);
    return i+j;
}

int EccEncryptT(CurveContext src,Entropy ELib,Byte *Msg,int Len)
{
    if(src==NULL)return Fail;
    if(src->IsCulPublic==0)
    {
        LastErrorCode=Error_ECC_Public;
        return Fail;
    }
    if(Msg==NULL)
    {
        LastErrorCode=Error_ECC_Msg;
        return Fail;
    }
    if(Len<=0)
    {
        LastErrorCode=Error_ECC_Len;
        return Fail;
    }

    Digit_32 L=(src->Bit+7)>>3,L2=L<<1,LL=2*L+32+Len;
    Byte *Temp=(Byte*)malloc(LL);
    int i;
    if(Temp==NULL)
    {
        LastErrorCode=Error_MallocFail;
        return Fail;
    }

    if(ElRandom(ELib,&src->LNTemp.Temp,L)==Fail)goto FailProc;
    //char K[64]="59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D64B80DEAC1BC21";
    //if(LnSetFromHex(&src->LNTemp.Temp,K,64)==Fail)goto FailProc;
    if(LnModule(&src->LNTemp.Temp,&src->Param.N,&src->Param.NT,&src->LNTemp)==Fail)goto FailProc;

    if(PointMul(&src->Param.G,&src->LNTemp.Temp,&src->CurveTemp.TempP0,&src->CurveTemp,&src->Param.A,&src->Param.P,&src->Param.PT,&src->LNTemp)==Fail)goto FailProc;
    LnOutputByte(&src->CurveTemp.TempP0.X,Temp,L);
    LnOutputByte(&src->CurveTemp.TempP0.Y,Temp+L,L);

    Temp+=L2;
    for(i=0;i<Len;i++)Temp[i]=Msg[i];
    Temp-=L2;

    SHA256T(Temp,LL-32,Temp+LL-32);
    //SM3T(Temp,2*L+Len,Temp+2*L+Len);

    if(PointMul(&src->Param.Public,&src->LNTemp.Temp,&src->CurveTemp.TempP1,&src->CurveTemp,&src->Param.A,&src->Param.P,&src->Param.PT,&src->LNTemp)==Fail)goto FailProc;
    LnOutputByte(&src->CurveTemp.TempP1.X,Temp,L);
    LnOutputByte(&src->CurveTemp.TempP1.Y,Temp+L,L);

    KDFFromSHA256(Temp,L2,Len,Temp+L2);

    Temp+=L2;
    for(i=0;i<Len;i++)Temp[i]^=Msg[i];
    Temp-=L2;

    LnOutputByte(&src->CurveTemp.TempP0.X,Temp,L);
    LnOutputByte(&src->CurveTemp.TempP0.Y,Temp+L,L);

    src->CipherText=Temp;
    src->CipherTextLen=LL;

    return LL;

    FailProc:
    free(Temp);
    return Fail;
}

int EccGetCipherTextT(CurveContext src,Byte *Buf,int Len)
{
    if(src==NULL)return Fail;
    if(Buf==NULL)
    {
        LastErrorCode=Error_ECC_Buf;
        return Fail;
    }
    if(Len<=0)
    {
        LastErrorCode=Error_ECC_Len;
        return Fail;
    }
    if(src->CipherText==NULL)return Success;
    int i;
    for(i=0;i<Len;i++)
    {
        Buf[i]=src->CipherText[i];
        if(i==src->CipherTextLen-1)break;
    }
    free(src->CipherText);
    src->CipherText=NULL;
    src->CipherTextLen=0;
    return i+1;
}

int EccDecryptT(CurveContext src,Byte *Msg,int Len)
{
    if(src==NULL)return Fail;
    if(src->Param.D.MSB==0)
    {
        LastErrorCode=Error_ECC_Private;
        return Fail;
    }
    Digit_32 L=(src->Bit+7)>>3,L2=2*L;
    if(Msg==NULL)
    {
        LastErrorCode=Error_ECC_Msg;
        return Fail;
    }
    if(Len<=L2+32)
    {
        LastErrorCode=Error_ECC_Len;
        return Fail;
    }

    src->PlainTextLen=Len-L2-32;
    int i;

    if(LnSetFromByte(&src->CurveTemp.TempP0.X,Msg,L)==Fail)return Fail;
    if(LnSetFromByte(&src->CurveTemp.TempP0.Y,Msg+L,L)==Fail)return Fail;

    if(PointMul(&src->CurveTemp.TempP0,&src->Param.D,&src->CurveTemp.TempP1,&src->CurveTemp,&src->Param.A,&src->Param.P,&src->Param.PT,&src->LNTemp)==Fail)return Fail;

    Byte Hash[32]={0};
    Byte *Cache=(Byte*)malloc(Len-32);
    if(Cache==NULL)
    {
        LastErrorCode=Error_MallocFail;
        return Fail;
    }

    LnOutputByte(&src->CurveTemp.TempP1.X,Cache,L);
    LnOutputByte(&src->CurveTemp.TempP1.Y,Cache+L,L);

    KDFFromSHA256(Cache,L2,src->PlainTextLen,Cache+L2);

    src->PlainTextLen+=L2;
    for(i=L<<1;i<src->PlainTextLen;i++)Cache[i]^=Msg[i];
    src->PlainTextLen-=L2;

    for(i=0;i<L2;i++)Cache[i]=Msg[i];
    SHA256T(Cache,Len-32,Hash);
    //SM3T(Cache,Len-32,Hash);
    for(i=0;i<32;i++)
    {
        if(Hash[i]!=Msg[i+Len-32])
        {
            free(Cache);
            return 0;
        }
    }

    src->PlainText=(Byte*)malloc(src->PlainTextLen);
    if(src->PlainText==NULL)
    {
        LastErrorCode=Error_MallocFail;
        free(Cache);
        return Fail;
    }

    for(i=0;i<src->PlainTextLen;i++)src->PlainText[i]=Cache[L2+i];
    free(Cache);
    return src->PlainTextLen;
}

int EccGetPlainTextT(CurveContext src,Byte *dest,int Len)
{
    if(src==NULL)return Fail;
    if(dest==NULL)
    {
        LastErrorCode=Error_ECC_Buf;
        return Fail;
    }
    if(Len<=0)
    {
        LastErrorCode=Error_ECC_Len;
        return Fail;
    }
    if(src->PlainText==NULL)return Success;
    int i;
    for(i=0;i<Len;i++)
    {
        dest[i]=src->PlainText[i];
        if(i==src->PlainTextLen-1)break;
    }
    free(src->PlainText);
    src->PlainText=NULL;
    src->PlainTextLen=0;
    return i+1;
}

int EccInputSignT(CurveContext src,Byte *Signature,int Len)
{
    if(src==NULL)return Fail;
    
    Digit_32 L=((src->Bit+7)>>3),LL;
    Byte *Temp,Cache;
    int i;
    if(Signature==NULL)
    {
        Temp=(Byte*)malloc(6*L);
        if(Temp==NULL)
        {
            LastErrorCode=Error_MallocFail;
            return Fail;
        }
        LL=0;
    }
    else
    {
        if(Len<=0)
        {
            LastErrorCode=Error_ECC_Len;
            return Fail;
        }
        Temp=(Byte*)malloc(6*L+Len);
        if(Temp==NULL)
        {
            LastErrorCode=Error_MallocFail;
            return Fail;
        }
        LL=Len;
        for(i=0;i<Len;i++)Temp[i]=Signature[i];
        Temp+=Len;
    }
    LnOutputByte(&src->Param.A,Temp,L);
    Temp+=L;
    LnOutputByte(&src->Param.B,Temp,L);
    Temp+=L;
    LnOutputByte(&src->Param.G.X,Temp,L);
    Temp+=L;
    LnOutputByte(&src->Param.G.Y,Temp,L);
    Temp+=L;
    LnOutputByte(&src->Param.Public.X,Temp,L);
    Temp+=L;
    LnOutputByte(&src->Param.Public.Y,Temp,L);
    Temp-=(5*L+LL);
    //printf("\nSign(%d):\n",6*L+LL);
    //for(i=0;i<6*L+LL;i++)printf("%02X",Temp[i]);
    SHA256T(Temp,6*L+LL,src->Sign);
    //SM3T(Temp,6*L+LL,UserSignature);
    free(Temp);
    src->IsInputSign=1;
    return Success;
}

int EccDigestT(CurveContext src,Entropy ELib,Byte *Msg,int Len)
{
    if(src==NULL)return Fail;
    if(Msg==NULL)
    {
        LastErrorCode=Error_ECC_Msg;
        return Fail;
    }
    if(Len<=0)
    {
        LastErrorCode=Error_ECC_Len;
        return Fail;
    }

    if(src->IsInputSign==0)
    {
        LastErrorCode=Error_ECC_Signature;
        return Fail;
        /* if(EccInputSignT(src,NULL,0)==Fail)
        {
            LastErrorCode=Error_ECC_Signature;
            return Fail;
        } */
    }
    if(src->IsCulPublic==0)
    {
        LastErrorCode=Error_ECC_Public;
        return Fail;
    }

    Byte *MsgT=(Byte*)malloc(Len+32);
    if(MsgT==NULL)
    {
        LastErrorCode=Error_MallocFail;
        return Fail;
    }

    int i;
    for(i=0;i<32;i++)MsgT[i]=src->Sign[i];
    for(i=0;i<Len;i++)MsgT[i+32]=Msg[i];
    

    Byte HashT[32]={0};
    SHA256T(MsgT,(Digit_64)(Len+32),HashT);
    //SM3T(MsgT,(Len+32),HashT);

    //对于长度超过256bit的椭圆曲线，可以使用KDF函数对HashT处理，使得HashT增长到与椭圆曲线相同的bit长度，这样加密性更好
    free(MsgT);

    //&src->LNTemp.Temp作为随机数k
    if(ElRandom(ELib,&src->LNTemp.Temp,(src->Bit+7)>>3)==Fail)return Fail;
    //char K[64]="59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D64B80DEAC1BC21";
    //if(LnSetFromHex(&src->LNTemp.Temp,K,64)==Fail)return Fail;
    if(LnModule(&src->LNTemp.Temp,&src->Param.N,&src->Param.NT,&src->LNTemp)==Fail)return Fail;

    if(PointMul(&src->Param.G,&src->LNTemp.Temp,&src->CurveTemp.TempP0,&src->CurveTemp,&src->Param.A,&src->Param.P,&src->Param.PT,&src->LNTemp)==Fail)return Fail;

    //计算[k]G点后，G点的Y坐标是不用的，所以接下来借用为临时大数容器
    //同时，TempP1也是不用的，借来当临时大数容器

    //&src->CurveTemp.TempP0.Y 导入哈希值当做大数e
    if(LnSetFromByte(&src->CurveTemp.TempP0.Y,HashT,32)==Fail)return Fail;

    //申请内存
    Digit_32 L=2*((src->Bit+7)>>3);
    Byte *Temp=(Byte*)malloc(L);

    //计算r=e+x1(x1是[k]G的X坐标)
    if(LnPlusMod(&src->CurveTemp.TempP0.Y,&src->CurveTemp.TempP0.X,&src->Param.N,&src->Param.NT,&src->LNTemp)==Fail)goto FailProc;
    i=LnOutputByte(&src->CurveTemp.TempP0.Y,Temp,L);

    //计算&src->CurveTemp.TempP1.X=(1+D)
    if(LnAssign(&src->CurveTemp.TempP1.X,&src->Param.D)==Fail)return Fail;
    if(LnPlusInt(&src->CurveTemp.TempP1.X,1)==Fail)return Fail;

    //计算&src->CurveTemp.TempP1.X=(1+D)^-1
    if(LnInverseElement(&src->CurveTemp.TempP1.X,&src->Param.N,&src->Param.NT,&src->LNTemp)==Fail)goto FailProc;

    //计算R=(r*D)
    if(LnMultiplyMod(&src->CurveTemp.TempP0.Y,&src->Param.D,&src->Param.N,&src->Param.NT,&src->LNTemp)==Fail)goto FailProc;
    
    //计算K=k-R
    if(LnMinusMod(&src->LNTemp.Temp,&src->CurveTemp.TempP0.Y,&src->Param.N,&src->Param.NT,&src->LNTemp)==Fail)goto FailProc;

    //计算s=K*(1+D)^-1
    if(LnMultiplyMod(&src->LNTemp.Temp,&src->CurveTemp.TempP1.X,&src->Param.N,&src->Param.NT,&src->LNTemp)==Fail)goto FailProc;
    LnOutputByte(&src->LNTemp.Temp,Temp+i,L);

    src->DigestText=Temp;

    return Success;

    FailProc:
    free(Temp);
    return Fail;
}

int EccGetDigestTextT(CurveContext src,Byte *dest,int Len)
{
    if(src==NULL)return Fail;
    if(dest==NULL)
    {
        LastErrorCode=Error_ECC_Buf;
        return Fail;
    }
    if(Len<=0)
    {
        LastErrorCode=Error_ECC_Len;
        return Fail;
    }
    if(src->DigestText==NULL)return Success;
    int i,L=2*((src->Bit+7)>>3)-1;
    for(i=0;i<Len;i++)
    {
        dest[i]=src->DigestText[i];
        if(i==L)break;
    }
    free(src->DigestText);
    src->DigestText=NULL;
    return i+1;
}

int EccVerifyT(CurveContext src,Byte *Msg,int Len,Byte *Digest,int dLen)
{
    if(src==NULL)return Fail;
    if(src->IsCulPublic==0)
    {
        LastErrorCode=Error_ECC_Public;
        return Fail;
    }
    if((dLen&1)==1)
    {
        LastErrorCode=Error_ECC_dLen;
        return Fail;
    }

    int L=dLen>>1;

    //载入s
    if(LnSetFromByte(&src->LNTemp.Temp,Digest+L,L)==Fail)return Fail;
    
    //计算[s]G
    if(PointMul(&src->Param.G,&src->LNTemp.Temp,&src->CurveTemp.TempP0,&src->CurveTemp,&src->Param.A,&src->Param.P,&src->Param.PT,&src->LNTemp)==Fail)return Fail;

    //这时候，&src->CurveTemp.TempJ0.X是未用到的大数，借来存储r
    if(LnSetFromByte(&src->CurveTemp.TempJ0.X,Digest,L)==Fail)return Fail;

    //计算s=s+r
    if(LnPlusMod(&src->LNTemp.Temp,&src->CurveTemp.TempJ0.X,&src->Param.N,&src->Param.NT,&src->LNTemp)==Fail)return Fail;

    //计算[s+r]Public
    if(PointMul(&src->Param.Public,&src->LNTemp.Temp,&src->CurveTemp.TempP1,&src->CurveTemp,&src->Param.A,&src->Param.P,&src->Param.PT,&src->LNTemp)==Fail)return Fail;

    //先转换到Jacobian坐标系上的点
    if(PointToJPoint(&src->CurveTemp.TempJ0,&src->CurveTemp.TempP0)==Fail)return Fail;
    if(PointToJPoint(&src->CurveTemp.TempJ1,&src->CurveTemp.TempP1)==Fail)return Fail;

    //计算P0=P0+P1(Jacobian坐标系下)
    if(JPointPlus(&src->CurveTemp.TempJ0,&src->CurveTemp.TempJ1,&src->CurveTemp,&src->Param.P,&src->Param.PT,&src->LNTemp)==Fail)return Fail;

    //将计算后的Jobian坐标转换到仿射坐标
    if(JPointToPoint(&src->CurveTemp.TempP0,&src->CurveTemp.TempJ0,&src->CurveTemp,&src->Param.P,&src->Param.PT,&src->LNTemp)==Fail)return Fail;
    
    //申请内存
    Byte *MsgT=(Byte*)malloc(Len+32);
    if(MsgT==NULL)
    {
        LastErrorCode=Error_MallocFail;
        return Fail;
    }

    int i;
    for(i=0;i<32;i++)MsgT[i]=src->Sign[i];
    for(i=0;i<Len;i++)MsgT[i+32]=Msg[i];

    //计算哈希值 HsahT
    Byte HashT[32]={0};
    SHA256T(MsgT,(Digit_64)(Len+32),HashT);
    //SM3T(MsgT,Len+32,HashT);
    free(MsgT);

    //载入HashT当做大数e
    if(LnSetFromByte(&src->LNTemp.Temp,HashT,32)==Fail)return Fail;

    //计算e+x1
    if(LnPlusMod(&src->LNTemp.Temp,&src->CurveTemp.TempP0.X,&src->Param.N,&src->Param.NT,&src->LNTemp)==Fail)return Fail;
    

    //这时候，&src->CurveTemp.TempP0.Y是未用到的大数，借来存储r
    if(LnSetFromByte(&src->CurveTemp.TempP0.Y,Digest,L)==Fail)return Fail;
    
    return LnEqual(&src->LNTemp.Temp,&src->CurveTemp.TempP0.Y);
}

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

int ECC_Encrypt_Test(int CurveID)
{
    Byte kk[64]="59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D64B80DEAC1BC21";
    Byte dd[131]="3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B83945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8394";
    Byte pp[263]={0};
    Byte CT[21]="MoFChen QQ:1586731648";
    int i,j;
    CurveContext ECC;
    Entropy ELib;

    ECC=EccInitT(CurveID);
    ELib=ElInit(96);

    ElInput(ELib,CT,21,0);
    ElInput(ELib,kk,64,1);
    ElInput(ELib,dd,131,0);
    ElPrint(ELib);

    /* LnPrint(&ECC->Param.P);
    LnPrint(&ECC->Param.A);
    LnPrint(&ECC->Param.B);
    LnPrint(&ECC->Param.N);
    LnPrint(&ECC->Param.G.X);
    LnPrint(&ECC->Param.G.Y);
    LnPrint(&ECC->Param.PT);
    LnPrint(&ECC->Param.NT); */

    if(ECC==NULL)return 0;
    EccInputPriKeyT(ECC,dd,(ECC->Bit+3)>>2);

    i=EccOutputPriKeyT(ECC,pp,262);
    printf("\nD(%d):\n",i);
    for(j=0;j<i;j++)printf("%c",pp[j]);
    printf("\n");

    EccCulPKeyT(ECC);

    i=EccOutputPubKeyT(ECC,pp,262);
    printf("\nPublic(%d):\n",i);
    for(j=0;j<i;j++)printf("%c",pp[j]);
    printf("\n");

    printf("\nText(%d):\n",21);
    for(j=0;j<21;j++)printf("%02X",CT[j]);
    printf("\n");

    i=EccEncryptT(ECC,ELib,CT,21);

    printf("\nCipherText(%d):\n",i);
    for(j=0;j<i;j++)printf("%02X",ECC->CipherText[j]);
    printf("\n");

    i=EccDecryptT(ECC,ECC->CipherText,i);

    /* printf("\nPlainText(%d):\n",i);
    for(j=0;j<i;j++)printf("%c",ECC->PlainText[j]);
    printf("\n"); */

    for(i=0;i<129;i++)pp[i]=0;
    i=EccGetPlainTextT(ECC,pp,262);
    printf("\nPlainText(%d):%s\n",i,pp);

    EccFreeT(ECC);
    ElFree(ELib);
    return 0;
}

int ECC_Digest_Test(int CurveID)
{
    Byte kk[64]="59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D64B80DEAC1BC21";
    Byte dd[131]="3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B83945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8394";
    Byte pp[263]={0};
    Byte Sign[18]={0,0x80,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
    Byte CT[21]="MoFChen QQ:1586731648";
    int i,j;
    CurveContext ECC;
    Entropy ELib;

    ECC=EccInitT(CurveID);
    ELib=ElInit(96);

    ElInput(ELib,CT,21,0);
    ElInput(ELib,kk,64,0);
    ElInput(ELib,dd,131,0);
    ElPrint(ELib);

    if(ECC==NULL)return 0;
    EccInputPriKeyT(ECC,dd,(ECC->Bit+3)>>2);

    i=EccOutputPriKeyT(ECC,pp,263);
    printf("\nD(%d):\n",i);
    for(j=0;j<i;j++)printf("%c",pp[j]);
    printf("\n");

    EccCulPKeyT(ECC);
    printf("\nIsCulPublic:%d\n",ECC->IsCulPublic);

    i=EccOutputPubKeyT(ECC,pp,263);
    printf("\nPublic(%d):\n",i);
    for(j=0;j<i;j++)printf("%c",pp[j]);
    printf("\n");

    printf("\nText(%d):\n",21);
    for(j=0;j<21;j++)printf("%02X",CT[j]);
    printf("\n");

    EccInputSignT(ECC,Sign,18);
    printf("\nHash:\n");
    for(i=0;i<32;i++)printf("%02X",ECC->Sign[i]);
    printf("\n");

    i=EccDigestT(ECC,ELib,CT,21);

    for(i=0;i<129;i++)pp[i]=0;
    i=EccGetDigestTextT(ECC,pp,263);
    printf("\nDigestText(%d):\n",i);
    for(j=0;j<i;j++)printf("%02X",pp[j]);
    printf("\n");

    i=EccVerifyT(ECC,CT,21,pp,i);

    printf("\nPlainText:(%d)",i);
    if(i==-1)printf("Error!");
    else if(i==0)printf("Fail!");
    else printf("Success!");
    printf("\n");

    EccFreeT(ECC);
    return 0;
}

int main()
{
    // printf("struct LN:%d\n",sizeof(s_LN));
    // printf("struct Point:%d\n",sizeof(s_Point));
    // printf("struct JPoint:%d\n",sizeof(s_JPoint));
    // printf("struct CurveParam:%d\n",sizeof(CurveParam));
    // printf("struct CurveT:%d\n",sizeof(CurveT));
    // printf("struct LNT:%d\n",sizeof(LNT));
    // printf("struct CurveContext:%d\n",sizeof(struct CurveContext));
    // printf("struct Entropy:%d\n",sizeof(struct Entropy));
    int CurveID=ECC_prime192v1;
    printf("C_ECC_SM2_Encrypt\n");
    ECC_Encrypt_Test(CurveID);
    printf("C_ECC_SM2_Digest\n");
    ECC_Digest_Test(CurveID);
    return 0;
}

//EOF