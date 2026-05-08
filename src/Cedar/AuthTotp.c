// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// AuthTotp.c
// TOTP (RFC 6238) implementation for SoftEther VPN

#include "AuthTotp.h"

static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Base32 encode
static UINT Base32Encode(char *dst, UINT dst_size, const UCHAR *src, UINT src_size)
{
	UINT i, dst_len = 0;
	UINT bit_offset = 0;
	UINT64 buffer = 0;

	// Validate arguments
	if (dst == NULL || src == NULL || dst_size == 0)
	{
		return 0;
	}

	for (i = 0; i < src_size; i++)
	{
		buffer = (buffer << 8) | src[i];
		bit_offset += 8;

		while (bit_offset >= 5)
		{
			if (dst_len >= dst_size - 1)
			{
				return dst_len;
			}
			bit_offset -= 5;
			dst[dst_len++] = base32_alphabet[(buffer >> bit_offset) & 0x1F];
		}
	}

	if (bit_offset > 0 && dst_len < dst_size - 1)
	{
		dst[dst_len++] = base32_alphabet[(buffer << (5 - bit_offset)) & 0x1F];
	}

	dst[dst_len] = '\0';
	return dst_len;
}

// Base32 decode
static UINT Base32Decode(UCHAR *dst, UINT dst_size, const char *src)
{
	UINT i, src_len, dst_len = 0;
	UINT bit_offset = 0;
	UINT64 buffer = 0;

	// Validate arguments
	if (dst == NULL || src == NULL || dst_size == 0)
	{
		return 0;
	}

	src_len = StrLen((char *)src);

	for (i = 0; i < src_len; i++)
	{
		char c = src[i];
		UINT value;

		if (c >= 'A' && c <= 'Z')
		{
			value = c - 'A';
		}
		else if (c >= '2' && c <= '7')
		{
			value = c - '2' + 26;
		}
		else
		{
			continue;
		}

		buffer = (buffer << 5) | value;
		bit_offset += 5;

		if (bit_offset >= 8)
		{
			if (dst_len >= dst_size)
			{
				return dst_len;
			}
			bit_offset -= 8;
			dst[dst_len++] = (UCHAR)((buffer >> bit_offset) & 0xFF);
		}
	}

	return dst_len;
}

// Generate a random TOTP secret
void TotpGenerateSecret(char *secret, UINT size)
{
	UCHAR random_bytes[10];

	// Validate arguments
	if (secret == NULL || size < 17)
	{
		return;
	}

	Rand(random_bytes, sizeof(random_bytes));
	Base32Encode(secret, size, random_bytes, sizeof(random_bytes));
}

// Truncate HMAC-SHA1 result to dynamic binary code
static UINT TruncateHmac(const UCHAR *hmac_result)
{
	UINT offset = hmac_result[19] & 0x0F;
	return
		((hmac_result[offset] & 0x7F) << 24) |
		((hmac_result[offset + 1] & 0xFF) << 16) |
		((hmac_result[offset + 2] & 0xFF) << 8) |
		(hmac_result[offset + 3] & 0xFF);
}

// Generate TOTP code at a specific counter step
static void TotpGenerateCodeAtStep(char *code, UINT code_size, const char *secret, UINT64 counter)
{
	UCHAR key[20];
	UINT key_len;
	UCHAR counter_be[8];
	UCHAR hmac_result[SHA1_SIZE];
	UINT truncated;
	UINT i;

	// Validate arguments
	if (code == NULL || secret == NULL)
	{
		return;
	}

	key_len = Base32Decode(key, sizeof(key), secret);
	if (key_len == 0)
	{
		return;
	}

	for (i = 0; i < 8; i++)
	{
		counter_be[i] = (UCHAR)((counter >> (56 - i * 8)) & 0xFF);
	}

	HMacSha1(hmac_result, key, key_len, counter_be, sizeof(counter_be));

	truncated = TruncateHmac(hmac_result);
	truncated %= 1000000;

	Format(code, code_size, "%06u", truncated);
}

// Generate TOTP code with time offset
void TotpGenerateCode(char *code, UINT code_size, const char *secret, UINT64 time_offset)
{
	UINT64 now = SystemTime64() / 1000;
	UINT64 counter = (now + time_offset) / TOTP_TIME_STEP;

	TotpGenerateCodeAtStep(code, code_size, secret, counter);
}

// Verify TOTP code with window
bool TotpVerifyCode(const char *secret, const char *code, UINT64 time_offset)
{
	char generated[TOTP_CODE_SIZE];
	UINT64 now = SystemTime64() / 1000;
	UINT64 base_counter = now / TOTP_TIME_STEP;
	int i;

	// Validate arguments
	if (secret == NULL || code == NULL)
	{
		return false;
	}

	for (i = -TOTP_WINDOW_SIZE; i <= TOTP_WINDOW_SIZE; i++)
	{
		TotpGenerateCodeAtStep(generated, sizeof(generated), secret, base_counter + i);
		if (StrCmpi(generated, (char *)code) == 0)
		{
			return true;
		}
	}

	return false;
}

// Generate otpauth:// URI for QR code
void TotpGenerateUri(wchar_t *uri, UINT uri_size, const char *secret, const char *issuer, const char *username)
{
	char uri_buf[512];

	// Validate arguments
	if (uri == NULL || secret == NULL || issuer == NULL || username == NULL)
	{
		return;
	}

	Format(uri_buf, sizeof(uri_buf),
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		issuer, username, secret, issuer, TOTP_CODE_DIGITS, TOTP_TIME_STEP);

	StrToUni(uri, uri_size, uri_buf);
}
