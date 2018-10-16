/* Created by "go tool cgo" - DO NOT EDIT. */

/* package command-line-arguments */


#line 1 "cgo-builtin-prolog"

#include <stddef.h> /* for ptrdiff_t below */

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

typedef struct { const char *p; ptrdiff_t n; } _GoString_;

#endif

/* Start of preamble from import "C" comments.  */


#line 19 "/home/ethbot/src/github.com/afterether/eacct/eacct.go"

#include <stdlib.h>
#include <string.h>

#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

typedef _GoString_ GoString;
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif


extern int Generate_account(void* p0, void* p1, void* p2);

extern int Generate_key(void* p0, int* p1, void* p2);

extern int Encrypt_key(void* p0, int* p1, void* p2, int p3, char* p4);

extern void Bigint_Add(void* p0, int* p1, char* p2, char* p3);

extern void Bigint_Sub(void* p0, int* p1, char* p2, char* p3);

extern void Bigint_Mul(void* p0, int* p1, char* p2, char* p3);

extern int Bigint_Cmp(char* p0, char* p1);

extern int NewKeyFromECDSA(void* p0, int* p1, char* p2);

extern int DecryptKeyFromJSON(void* p0, int* p1, char* p2, char* p3);

extern int SignTransaction(void* p0, int* p1, void* p2, char* p3, char* p4, int p5, char* p6, char* p7, int p8, char* p9, char* p10, char* p11);

extern int DecodeTransaction(void* p0, int* p1, char* p2, int p3);

extern int EncodeInput4ContractCall(void* p0, int* p1, int p2, char* p3, char* p4, char* p5);

extern int ABI_Methods(void* p0, int* p1, int p2, char* p3);

#ifdef __cplusplus
}
#endif
