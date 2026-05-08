// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// AuthTotp.h
// Header of AuthTotp.c

#ifndef	AUTHTOTP_H
#define	AUTHTOTP_H

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Str.h"

#define	TOTP_SECRET_SIZE		64
#define	TOTP_CODE_SIZE			8
#define	TOTP_TIME_STEP			30
#define	TOTP_CODE_DIGITS		6
#define	TOTP_WINDOW_SIZE		1

void TotpGenerateSecret(char *secret, UINT size);
void TotpGenerateCode(char *code, UINT code_size, const char *secret, UINT64 time_offset);
bool TotpVerifyCode(const char *secret, const char *code, UINT64 time_offset);
void TotpGenerateUri(wchar_t *uri, UINT uri_size, const char *secret, const char *issuer, const char *username);

#endif
