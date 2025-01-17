#pragma once

#include "types.h"

/*! \file int8x16.h
    \brief Provides 128bit sixteen-element signed 8-bit integer SIMD operations which are mapped to equivalent SSE2 or Neon operations.
*/

#ifdef __cplusplus
extern "C" {
#endif

#if defined(KINC_SSE2)

static inline kinc_int8x16_t kinc_int8x16_load(const int8_t values[16]) {
	return _mm_set_epi8(values[15], values[14], values[13], values[12], values[11], values[10], values[9], values[8], values[7], values[6], values[5],
	                    values[4], values[3], values[2], values[1], values[0]);
}

static inline kinc_int8x16_t kinc_int8x16_load_all(int8_t t) {
	return _mm_set1_epi8(t);
}

static inline int8_t kinc_int8x16_get(kinc_int8x16_t t, int index) {
	union {
		__m128i value;
		int8_t elements[16];
	} converter;
	converter.value = t;
	return converter.elements[index];
}

static inline kinc_int8x16_t kinc_int8x16_add(kinc_int8x16_t a, kinc_int8x16_t b) {
	return _mm_add_epi8(a, b);
}

static inline kinc_int8x16_t kinc_int8x16_sub(kinc_int8x16_t a, kinc_int8x16_t b) {
	return _mm_sub_epi8(a, b);
}

static inline kinc_int8x16_t kinc_int8x16_max(kinc_int8x16_t a, kinc_int8x16_t b) {
	__m128i mask = _mm_cmpgt_epi8(a, b);
	return _mm_xor_si128(b, _mm_and_si128(mask, _mm_xor_si128(a, b)));
}

static inline kinc_int8x16_t kinc_int8x16_min(kinc_int8x16_t a, kinc_int8x16_t b) {
	__m128i mask = _mm_cmplt_epi8(a, b);
	return _mm_xor_si128(b, _mm_and_si128(mask, _mm_xor_si128(a, b)));
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmpeq(kinc_int8x16_t a, kinc_int8x16_t b) {
	return _mm_cmpeq_epi8(a, b);
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmpge(kinc_int8x16_t a, kinc_int8x16_t b) {
	return _mm_or_si128(_mm_cmpgt_epi8(a, b), _mm_cmpeq_epi8(a, b));
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmpgt(kinc_int8x16_t a, kinc_int8x16_t b) {
	return _mm_cmpgt_epi8(a, b);
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmple(kinc_int8x16_t a, kinc_int8x16_t b) {
	return _mm_or_si128(_mm_cmplt_epi8(a, b), _mm_cmpeq_epi8(a, b));
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmplt(kinc_int8x16_t a, kinc_int8x16_t b) {
	return _mm_cmplt_epi8(a, b);
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmpneq(kinc_int8x16_t a, kinc_int8x16_t b) {
	__m128i mask = _mm_cmpeq_epi8(a, b);
	__m128i all = _mm_set1_epi32(0xffffffff);
	return _mm_andnot_si128(mask, all);
}

static inline kinc_int8x16_t kinc_int8x16_sel(kinc_int8x16_t a, kinc_int8x16_t b, kinc_int8x16_mask_t mask) {
	return _mm_xor_si128(b, _mm_and_si128(mask, _mm_xor_si128(a, b)));
}

static inline kinc_int8x16_t kinc_int8x16_or(kinc_int8x16_t a, kinc_int8x16_t b) {
	return _mm_or_si128(a, b);
}

static inline kinc_int8x16_t kinc_int8x16_and(kinc_int8x16_t a, kinc_int8x16_t b) {
	return _mm_and_si128(a, b);
}

static inline kinc_int8x16_t kinc_int8x16_xor(kinc_int8x16_t a, kinc_int8x16_t b) {
	return _mm_xor_si128(a, b);
}

static inline kinc_int8x16_t kinc_int8x16_not(kinc_int8x16_t t) {
	__m128i mask = _mm_set1_epi32(0xffffffff);
	return _mm_xor_si128(t, mask);
}

#elif defined(KINC_NEON)

static inline kinc_int8x16_t kinc_int8x16_load(const int8_t values[16]) {
	return (kinc_int8x16_t){values[0], values[1], values[2],  values[3],  values[4],  values[5],  values[6],  values[7],
	                        values[8], values[9], values[10], values[11], values[12], values[13], values[14], values[15]};
}

static inline kinc_int8x16_t kinc_int8x16_load_all(int8_t t) {
	return (kinc_int8x16_t){t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t};
}

static inline int8_t kinc_int8x16_get(kinc_int8x16_t t, int index) {
	return t[index];
}

static inline kinc_int8x16_t kinc_int8x16_add(kinc_int8x16_t a, kinc_int8x16_t b) {
	return vaddq_s8(a, b);
}

static inline kinc_int8x16_t kinc_int8x16_sub(kinc_int8x16_t a, kinc_int8x16_t b) {
	return vsubq_s8(a, b);
}

static inline kinc_int8x16_t kinc_int8x16_max(kinc_int8x16_t a, kinc_int8x16_t b) {
	return vmaxq_s8(a, b);
}

static inline kinc_int8x16_t kinc_int8x16_min(kinc_int8x16_t a, kinc_int8x16_t b) {
	return vminq_s8(a, b);
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmpeq(kinc_int8x16_t a, kinc_int8x16_t b) {
	return vceqq_s8(a, b);
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmpge(kinc_int8x16_t a, kinc_int8x16_t b) {
	return vcgeq_s8(a, b);
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmpgt(kinc_int8x16_t a, kinc_int8x16_t b) {
	return vcgtq_s8(a, b);
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmple(kinc_int8x16_t a, kinc_int8x16_t b) {
	return vcleq_s8(a, b);
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmplt(kinc_int8x16_t a, kinc_int8x16_t b) {
	return vcltq_s8(a, b);
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmpneq(kinc_int8x16_t a, kinc_int8x16_t b) {
	return vmvnq_u8(vceqq_s8(a, b));
}

static inline kinc_int8x16_t kinc_int8x16_sel(kinc_int8x16_t a, kinc_int8x16_t b, kinc_int8x16_mask_t mask) {
	return vbslq_s8(mask, a, b);
}

static inline kinc_int8x16_t kinc_int8x16_or(kinc_int8x16_t a, kinc_int8x16_t b) {
	return vorrq_s8(a, b);
}

static inline kinc_int8x16_t kinc_int8x16_and(kinc_int8x16_t a, kinc_int8x16_t b) {
	return vandq_s8(a, b);
}

static inline kinc_int8x16_t kinc_int8x16_xor(kinc_int8x16_t a, kinc_int8x16_t b) {
	return veorq_s8(a, b);
}

static inline kinc_int8x16_t kinc_int8x16_not(kinc_int8x16_t t) {
	return vmvnq_s8(t);
}

#else

static inline kinc_int8x16_t kinc_int8x16_load(const int8_t values[16]) {
	kinc_int8x16_t value;
	value.values[0] = values[0];
	value.values[1] = values[1];
	value.values[2] = values[2];
	value.values[3] = values[3];
	value.values[4] = values[4];
	value.values[5] = values[5];
	value.values[6] = values[6];
	value.values[7] = values[7];
	value.values[8] = values[8];
	value.values[9] = values[9];
	value.values[10] = values[10];
	value.values[11] = values[11];
	value.values[12] = values[12];
	value.values[13] = values[13];
	value.values[14] = values[14];
	value.values[15] = values[15];
	return value;
}

static inline kinc_int8x16_t kinc_int8x16_load_all(int8_t t) {
	kinc_int8x16_t value;
	value.values[0] = t;
	value.values[1] = t;
	value.values[2] = t;
	value.values[3] = t;
	value.values[4] = t;
	value.values[5] = t;
	value.values[6] = t;
	value.values[7] = t;
	value.values[8] = t;
	value.values[9] = t;
	value.values[10] = t;
	value.values[11] = t;
	value.values[12] = t;
	value.values[13] = t;
	value.values[14] = t;
	value.values[15] = t;
	return value;
}

static inline int8_t kinc_int8x16_get(kinc_int8x16_t t, int index) {
	return t.values[index];
}

static inline kinc_int8x16_t kinc_int8x16_add(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_t value;
	value.values[0] = a.values[0] + b.values[0];
	value.values[1] = a.values[1] + b.values[1];
	value.values[2] = a.values[2] + b.values[2];
	value.values[3] = a.values[3] + b.values[3];
	value.values[4] = a.values[4] + b.values[4];
	value.values[5] = a.values[5] + b.values[5];
	value.values[6] = a.values[6] + b.values[6];
	value.values[7] = a.values[7] + b.values[7];
	value.values[8] = a.values[8] + b.values[8];
	value.values[9] = a.values[9] + b.values[9];
	value.values[10] = a.values[10] + b.values[10];
	value.values[11] = a.values[11] + b.values[11];
	value.values[12] = a.values[12] + b.values[12];
	value.values[13] = a.values[13] + b.values[13];
	value.values[14] = a.values[14] + b.values[14];
	value.values[15] = a.values[15] + b.values[15];
	return value;
}

static inline kinc_int8x16_t kinc_int8x16_sub(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_t value;
	value.values[0] = a.values[0] - b.values[0];
	value.values[1] = a.values[1] - b.values[1];
	value.values[2] = a.values[2] - b.values[2];
	value.values[3] = a.values[3] - b.values[3];
	value.values[4] = a.values[4] - b.values[4];
	value.values[5] = a.values[5] - b.values[5];
	value.values[6] = a.values[6] - b.values[6];
	value.values[7] = a.values[7] - b.values[7];
	value.values[8] = a.values[8] - b.values[8];
	value.values[9] = a.values[9] - b.values[9];
	value.values[10] = a.values[10] - b.values[10];
	value.values[11] = a.values[11] - b.values[11];
	value.values[12] = a.values[12] - b.values[12];
	value.values[13] = a.values[13] - b.values[13];
	value.values[14] = a.values[14] - b.values[14];
	value.values[15] = a.values[15] - b.values[15];
	return value;
}

static inline kinc_int8x16_t kinc_int8x16_max(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_t value;
	value.values[0] = kinc_max(a.values[0], b.values[0]);
	value.values[1] = kinc_max(a.values[1], b.values[1]);
	value.values[2] = kinc_max(a.values[2], b.values[2]);
	value.values[3] = kinc_max(a.values[3], b.values[3]);
	value.values[4] = kinc_max(a.values[4], b.values[4]);
	value.values[5] = kinc_max(a.values[5], b.values[5]);
	value.values[6] = kinc_max(a.values[6], b.values[6]);
	value.values[7] = kinc_max(a.values[7], b.values[7]);
	value.values[8] = kinc_max(a.values[8], b.values[8]);
	value.values[9] = kinc_max(a.values[9], b.values[9]);
	value.values[10] = kinc_max(a.values[10], b.values[10]);
	value.values[11] = kinc_max(a.values[11], b.values[11]);
	value.values[12] = kinc_max(a.values[12], b.values[12]);
	value.values[13] = kinc_max(a.values[13], b.values[13]);
	value.values[14] = kinc_max(a.values[14], b.values[14]);
	value.values[15] = kinc_max(a.values[15], b.values[15]);
	return value;
}

static inline kinc_int8x16_t kinc_int8x16_min(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_t value;
	value.values[0] = kinc_min(a.values[0], b.values[0]);
	value.values[1] = kinc_min(a.values[1], b.values[1]);
	value.values[2] = kinc_min(a.values[2], b.values[2]);
	value.values[3] = kinc_min(a.values[3], b.values[3]);
	value.values[4] = kinc_min(a.values[4], b.values[4]);
	value.values[5] = kinc_min(a.values[5], b.values[5]);
	value.values[6] = kinc_min(a.values[6], b.values[6]);
	value.values[7] = kinc_min(a.values[7], b.values[7]);
	value.values[8] = kinc_min(a.values[8], b.values[8]);
	value.values[9] = kinc_min(a.values[9], b.values[9]);
	value.values[10] = kinc_min(a.values[10], b.values[10]);
	value.values[11] = kinc_min(a.values[11], b.values[11]);
	value.values[12] = kinc_min(a.values[12], b.values[12]);
	value.values[13] = kinc_min(a.values[13], b.values[13]);
	value.values[14] = kinc_min(a.values[14], b.values[14]);
	value.values[15] = kinc_min(a.values[15], b.values[15]);
	return value;
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmpeq(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_mask_t mask;
	mask.values[0] = a.values[0] == b.values[0] ? 0xff : 0;
	mask.values[1] = a.values[1] == b.values[1] ? 0xff : 0;
	mask.values[2] = a.values[2] == b.values[2] ? 0xff : 0;
	mask.values[3] = a.values[3] == b.values[3] ? 0xff : 0;
	mask.values[4] = a.values[4] == b.values[4] ? 0xff : 0;
	mask.values[5] = a.values[5] == b.values[5] ? 0xff : 0;
	mask.values[6] = a.values[6] == b.values[6] ? 0xff : 0;
	mask.values[7] = a.values[7] == b.values[7] ? 0xff : 0;
	mask.values[8] = a.values[8] == b.values[8] ? 0xff : 0;
	mask.values[9] = a.values[9] == b.values[9] ? 0xff : 0;
	mask.values[10] = a.values[10] == b.values[10] ? 0xff : 0;
	mask.values[11] = a.values[11] == b.values[11] ? 0xff : 0;
	mask.values[12] = a.values[12] == b.values[12] ? 0xff : 0;
	mask.values[13] = a.values[13] == b.values[13] ? 0xff : 0;
	mask.values[14] = a.values[14] == b.values[14] ? 0xff : 0;
	mask.values[15] = a.values[15] == b.values[15] ? 0xff : 0;
	return mask;
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmpge(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_mask_t mask;
	mask.values[0] = a.values[0] >= b.values[0] ? 0xff : 0;
	mask.values[1] = a.values[1] >= b.values[1] ? 0xff : 0;
	mask.values[2] = a.values[2] >= b.values[2] ? 0xff : 0;
	mask.values[3] = a.values[3] >= b.values[3] ? 0xff : 0;
	mask.values[4] = a.values[4] >= b.values[4] ? 0xff : 0;
	mask.values[5] = a.values[5] >= b.values[5] ? 0xff : 0;
	mask.values[6] = a.values[6] >= b.values[6] ? 0xff : 0;
	mask.values[7] = a.values[7] >= b.values[7] ? 0xff : 0;
	mask.values[8] = a.values[8] >= b.values[8] ? 0xff : 0;
	mask.values[9] = a.values[9] >= b.values[9] ? 0xff : 0;
	mask.values[10] = a.values[10] >= b.values[10] ? 0xff : 0;
	mask.values[11] = a.values[11] >= b.values[11] ? 0xff : 0;
	mask.values[12] = a.values[12] >= b.values[12] ? 0xff : 0;
	mask.values[13] = a.values[13] >= b.values[13] ? 0xff : 0;
	mask.values[14] = a.values[14] >= b.values[14] ? 0xff : 0;
	mask.values[15] = a.values[15] >= b.values[15] ? 0xff : 0;
	return mask;
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmpgt(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_mask_t mask;
	mask.values[0] = a.values[0] > b.values[0] ? 0xff : 0;
	mask.values[1] = a.values[1] > b.values[1] ? 0xff : 0;
	mask.values[2] = a.values[2] > b.values[2] ? 0xff : 0;
	mask.values[3] = a.values[3] > b.values[3] ? 0xff : 0;
	mask.values[4] = a.values[4] > b.values[4] ? 0xff : 0;
	mask.values[5] = a.values[5] > b.values[5] ? 0xff : 0;
	mask.values[6] = a.values[6] > b.values[6] ? 0xff : 0;
	mask.values[7] = a.values[7] > b.values[7] ? 0xff : 0;
	mask.values[8] = a.values[8] > b.values[8] ? 0xff : 0;
	mask.values[9] = a.values[9] > b.values[9] ? 0xff : 0;
	mask.values[10] = a.values[10] > b.values[10] ? 0xff : 0;
	mask.values[11] = a.values[11] > b.values[11] ? 0xff : 0;
	mask.values[12] = a.values[12] > b.values[12] ? 0xff : 0;
	mask.values[13] = a.values[13] > b.values[13] ? 0xff : 0;
	mask.values[14] = a.values[14] > b.values[14] ? 0xff : 0;
	mask.values[15] = a.values[15] > b.values[15] ? 0xff : 0;
	return mask;
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmple(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_mask_t mask;
	mask.values[0] = a.values[0] <= b.values[0] ? 0xff : 0;
	mask.values[1] = a.values[1] <= b.values[1] ? 0xff : 0;
	mask.values[2] = a.values[2] <= b.values[2] ? 0xff : 0;
	mask.values[3] = a.values[3] <= b.values[3] ? 0xff : 0;
	mask.values[4] = a.values[4] <= b.values[4] ? 0xff : 0;
	mask.values[5] = a.values[5] <= b.values[5] ? 0xff : 0;
	mask.values[6] = a.values[6] <= b.values[6] ? 0xff : 0;
	mask.values[7] = a.values[7] <= b.values[7] ? 0xff : 0;
	mask.values[8] = a.values[8] <= b.values[8] ? 0xff : 0;
	mask.values[9] = a.values[9] <= b.values[9] ? 0xff : 0;
	mask.values[10] = a.values[10] <= b.values[10] ? 0xff : 0;
	mask.values[11] = a.values[11] <= b.values[11] ? 0xff : 0;
	mask.values[12] = a.values[12] <= b.values[12] ? 0xff : 0;
	mask.values[13] = a.values[13] <= b.values[13] ? 0xff : 0;
	mask.values[14] = a.values[14] <= b.values[14] ? 0xff : 0;
	mask.values[15] = a.values[15] <= b.values[15] ? 0xff : 0;
	return mask;
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmplt(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_mask_t mask;
	mask.values[0] = a.values[0] < b.values[0] ? 0xff : 0;
	mask.values[1] = a.values[1] < b.values[1] ? 0xff : 0;
	mask.values[2] = a.values[2] < b.values[2] ? 0xff : 0;
	mask.values[3] = a.values[3] < b.values[3] ? 0xff : 0;
	mask.values[4] = a.values[4] < b.values[4] ? 0xff : 0;
	mask.values[5] = a.values[5] < b.values[5] ? 0xff : 0;
	mask.values[6] = a.values[6] < b.values[6] ? 0xff : 0;
	mask.values[7] = a.values[7] < b.values[7] ? 0xff : 0;
	mask.values[8] = a.values[8] < b.values[8] ? 0xff : 0;
	mask.values[9] = a.values[9] < b.values[9] ? 0xff : 0;
	mask.values[10] = a.values[10] < b.values[10] ? 0xff : 0;
	mask.values[11] = a.values[11] < b.values[11] ? 0xff : 0;
	mask.values[12] = a.values[12] < b.values[12] ? 0xff : 0;
	mask.values[13] = a.values[13] < b.values[13] ? 0xff : 0;
	mask.values[14] = a.values[14] < b.values[14] ? 0xff : 0;
	mask.values[15] = a.values[15] < b.values[15] ? 0xff : 0;
	return mask;
}

static inline kinc_int8x16_mask_t kinc_int8x16_cmpneq(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_mask_t mask;
	mask.values[0] = a.values[0] != b.values[0] ? 0xff : 0;
	mask.values[1] = a.values[1] != b.values[1] ? 0xff : 0;
	mask.values[2] = a.values[2] != b.values[2] ? 0xff : 0;
	mask.values[3] = a.values[3] != b.values[3] ? 0xff : 0;
	mask.values[4] = a.values[4] != b.values[4] ? 0xff : 0;
	mask.values[5] = a.values[5] != b.values[5] ? 0xff : 0;
	mask.values[6] = a.values[6] != b.values[6] ? 0xff : 0;
	mask.values[7] = a.values[7] != b.values[7] ? 0xff : 0;
	mask.values[8] = a.values[8] != b.values[8] ? 0xff : 0;
	mask.values[9] = a.values[9] != b.values[9] ? 0xff : 0;
	mask.values[10] = a.values[10] != b.values[10] ? 0xff : 0;
	mask.values[11] = a.values[11] != b.values[11] ? 0xff : 0;
	mask.values[12] = a.values[12] != b.values[12] ? 0xff : 0;
	mask.values[13] = a.values[13] != b.values[13] ? 0xff : 0;
	mask.values[14] = a.values[14] != b.values[14] ? 0xff : 0;
	mask.values[15] = a.values[15] != b.values[15] ? 0xff : 0;
	return mask;
}

static inline kinc_int8x16_t kinc_int8x16_sel(kinc_int8x16_t a, kinc_int8x16_t b, kinc_int8x16_mask_t mask) {
	kinc_int8x16_t value;
	value.values[0] = mask.values[0] != 0 ? a.values[0] : b.values[0];
	value.values[1] = mask.values[1] != 0 ? a.values[1] : b.values[1];
	value.values[2] = mask.values[2] != 0 ? a.values[2] : b.values[2];
	value.values[3] = mask.values[3] != 0 ? a.values[3] : b.values[3];
	value.values[4] = mask.values[4] != 0 ? a.values[4] : b.values[4];
	value.values[5] = mask.values[5] != 0 ? a.values[5] : b.values[5];
	value.values[6] = mask.values[6] != 0 ? a.values[6] : b.values[6];
	value.values[7] = mask.values[7] != 0 ? a.values[7] : b.values[7];
	value.values[8] = mask.values[8] != 0 ? a.values[8] : b.values[8];
	value.values[9] = mask.values[9] != 0 ? a.values[9] : b.values[9];
	value.values[10] = mask.values[10] != 0 ? a.values[10] : b.values[10];
	value.values[11] = mask.values[11] != 0 ? a.values[11] : b.values[11];
	value.values[12] = mask.values[12] != 0 ? a.values[12] : b.values[12];
	value.values[13] = mask.values[13] != 0 ? a.values[13] : b.values[13];
	value.values[14] = mask.values[14] != 0 ? a.values[14] : b.values[14];
	value.values[15] = mask.values[15] != 0 ? a.values[15] : b.values[15];
	return value;
}

static inline kinc_int8x16_t kinc_int8x16_or(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_t value;
	value.values[0] = a.values[0] | b.values[0];
	value.values[1] = a.values[1] | b.values[1];
	value.values[2] = a.values[2] | b.values[2];
	value.values[3] = a.values[3] | b.values[3];
	value.values[4] = a.values[4] | b.values[4];
	value.values[5] = a.values[5] | b.values[5];
	value.values[6] = a.values[6] | b.values[6];
	value.values[7] = a.values[7] | b.values[7];
	value.values[8] = a.values[8] | b.values[8];
	value.values[9] = a.values[9] | b.values[9];
	value.values[10] = a.values[10] | b.values[10];
	value.values[11] = a.values[11] | b.values[11];
	value.values[12] = a.values[12] | b.values[12];
	value.values[13] = a.values[13] | b.values[13];
	value.values[14] = a.values[14] | b.values[14];
	value.values[15] = a.values[15] | b.values[15];
	return value;
}

static inline kinc_int8x16_t kinc_int8x16_and(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_t value;
	value.values[0] = a.values[0] & b.values[0];
	value.values[1] = a.values[1] & b.values[1];
	value.values[2] = a.values[2] & b.values[2];
	value.values[3] = a.values[3] & b.values[3];
	value.values[4] = a.values[4] & b.values[4];
	value.values[5] = a.values[5] & b.values[5];
	value.values[6] = a.values[6] & b.values[6];
	value.values[7] = a.values[7] & b.values[7];
	value.values[8] = a.values[8] & b.values[8];
	value.values[9] = a.values[9] & b.values[9];
	value.values[10] = a.values[10] & b.values[10];
	value.values[11] = a.values[11] & b.values[11];
	value.values[12] = a.values[12] & b.values[12];
	value.values[13] = a.values[13] & b.values[13];
	value.values[14] = a.values[14] & b.values[14];
	value.values[15] = a.values[15] & b.values[15];
	return value;
}

static inline kinc_int8x16_t kinc_int8x16_xor(kinc_int8x16_t a, kinc_int8x16_t b) {
	kinc_int8x16_t value;
	value.values[0] = a.values[0] ^ b.values[0];
	value.values[1] = a.values[1] ^ b.values[1];
	value.values[2] = a.values[2] ^ b.values[2];
	value.values[3] = a.values[3] ^ b.values[3];
	value.values[4] = a.values[4] ^ b.values[4];
	value.values[5] = a.values[5] ^ b.values[5];
	value.values[6] = a.values[6] ^ b.values[6];
	value.values[7] = a.values[7] ^ b.values[7];
	value.values[8] = a.values[8] ^ b.values[8];
	value.values[9] = a.values[9] ^ b.values[9];
	value.values[10] = a.values[10] ^ b.values[10];
	value.values[11] = a.values[11] ^ b.values[11];
	value.values[12] = a.values[12] ^ b.values[12];
	value.values[13] = a.values[13] ^ b.values[13];
	value.values[14] = a.values[14] ^ b.values[14];
	value.values[15] = a.values[15] ^ b.values[15];
	return value;
}

static inline kinc_int8x16_t kinc_int8x16_not(kinc_int8x16_t t) {
	kinc_int8x16_t value;
	value.values[0] = ~t.values[0];
	value.values[1] = ~t.values[1];
	value.values[2] = ~t.values[2];
	value.values[3] = ~t.values[3];
	value.values[4] = ~t.values[4];
	value.values[5] = ~t.values[5];
	value.values[6] = ~t.values[6];
	value.values[7] = ~t.values[7];
	value.values[8] = ~t.values[8];
	value.values[9] = ~t.values[9];
	value.values[10] = ~t.values[10];
	value.values[11] = ~t.values[11];
	value.values[12] = ~t.values[12];
	value.values[13] = ~t.values[13];
	value.values[14] = ~t.values[14];
	value.values[15] = ~t.values[15];
	return value;
}

#endif

#ifdef __cplusplus
}
#endif
