#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "falcon.h"
#include "internal.h"

static uint8_t
hex_nibble(char c)
{
	if (c >= '0' && c <= '9') {
		return (uint8_t)(c - '0');
	}
	if (c >= 'a' && c <= 'f') {
		return (uint8_t)(10 + (c - 'a'));
	}
	if (c >= 'A' && c <= 'F') {
		return (uint8_t)(10 + (c - 'A'));
	}
	fprintf(stderr, "invalid hex digit: %c\n", c);
	exit(EXIT_FAILURE);
}

static uint8_t *
hex_to_bytes(const char *src, size_t *out_len)
{
	size_t len, u;
	uint8_t *out;

	len = strlen(src);
	if ((len & 1u) != 0) {
		fprintf(stderr, "hex string has odd length\n");
		exit(EXIT_FAILURE);
	}
	out = malloc(len >> 1);
	if (out == NULL) {
		fprintf(stderr, "allocation failure\n");
		exit(EXIT_FAILURE);
	}
	for (u = 0; u < len; u += 2) {
		out[u >> 1] = (uint8_t)((hex_nibble(src[u]) << 4) | hex_nibble(src[u + 1]));
	}
	*out_len = len >> 1;
	return out;
}

static void
print_hex_field(const char *name, const uint8_t *buf, size_t len)
{
	size_t u;

	printf("%s=", name);
	for (u = 0; u < len; u ++) {
		printf("%02x", buf[u]);
	}
	printf("\n");
}

static void
print_u16_hex_field(const char *name, const uint16_t *buf, size_t len)
{
	size_t u;

	printf("%s=", name);
	for (u = 0; u < len; u ++) {
		printf("%04x", (unsigned)buf[u]);
	}
	printf("\n");
}

static void
cmd_keygen(unsigned logn, const char *seed_hex, int comp)
{
	falcon_keygen *fk;
	size_t seed_len, sk_len, pk_len;
	uint8_t *seed, *sk, *pk;

	seed = hex_to_bytes(seed_hex, &seed_len);
	fk = falcon_keygen_new(logn, 0);
	if (fk == NULL) {
		fprintf(stderr, "falcon_keygen_new failed\n");
		exit(EXIT_FAILURE);
	}
	sk_len = falcon_keygen_max_privkey_size(fk);
	pk_len = falcon_keygen_max_pubkey_size(fk);
	sk = malloc(sk_len);
	pk = malloc(pk_len);
	if (sk == NULL || pk == NULL) {
		fprintf(stderr, "allocation failure\n");
		exit(EXIT_FAILURE);
	}

	falcon_keygen_set_seed(fk, seed, seed_len, 1);
	if (!falcon_keygen_make(fk, comp, sk, &sk_len, pk, &pk_len)) {
		fprintf(stderr, "falcon_keygen_make failed\n");
		exit(EXIT_FAILURE);
	}

	print_hex_field("SK", sk, sk_len);
	print_hex_field("PK", pk, pk_len);

	falcon_keygen_free(fk);
	free(seed);
	free(sk);
	free(pk);
}

static void
cmd_hash_to_point_binary(unsigned logn, const char *nonce_hex, const char *msg_hex)
{
	shake_context sc;
	size_t nonce_len, msg_len;
	uint8_t *nonce, *msg;
	uint16_t *c0;
	size_t n;

	nonce = hex_to_bytes(nonce_hex, &nonce_len);
	msg = hex_to_bytes(msg_hex, &msg_len);
	n = (size_t)1 << logn;
	c0 = malloc(n * sizeof *c0);
	if (c0 == NULL) {
		fprintf(stderr, "allocation failure\n");
		exit(EXIT_FAILURE);
	}

	shake_init(&sc, 512);
	shake_inject(&sc, nonce, nonce_len);
	shake_inject(&sc, msg, msg_len);
	shake_flip(&sc);
	falcon_hash_to_point(&sc, 12289, c0, logn);
	print_u16_hex_field("C0", c0, n);

	free(nonce);
	free(msg);
	free(c0);
}

static void
cmd_verify(const char *pk_hex, const char *nonce_hex,
	const char *msg_hex, const char *sig_hex)
{
	falcon_vrfy *fv;
	size_t pk_len, nonce_len, msg_len, sig_len;
	uint8_t *pk, *nonce, *msg, *sig;
	int status;

	pk = hex_to_bytes(pk_hex, &pk_len);
	nonce = hex_to_bytes(nonce_hex, &nonce_len);
	msg = hex_to_bytes(msg_hex, &msg_len);
	sig = hex_to_bytes(sig_hex, &sig_len);
	fv = falcon_vrfy_new();
	if (fv == NULL) {
		fprintf(stderr, "falcon_vrfy_new failed\n");
		exit(EXIT_FAILURE);
	}
	if (!falcon_vrfy_set_public_key(fv, pk, pk_len)) {
		fprintf(stderr, "falcon_vrfy_set_public_key failed\n");
		exit(EXIT_FAILURE);
	}
	falcon_vrfy_start(fv, nonce, nonce_len);
	falcon_vrfy_update(fv, msg, msg_len);
	status = falcon_vrfy_verify(fv, sig, sig_len);
	printf("STATUS=%d\n", status);

	falcon_vrfy_free(fv);
	free(pk);
	free(nonce);
	free(msg);
	free(sig);
}

static void
cmd_sign(const char *sk_hex, const char *msg_hex,
	const char *seed_hex, int comp)
{
	falcon_sign *fs;
	size_t sk_len, msg_len, seed_len, sig_len;
	uint8_t *sk, *msg, *seed, *sig;
	uint8_t nonce[40];
	size_t sig_max_len;

	sk = hex_to_bytes(sk_hex, &sk_len);
	msg = hex_to_bytes(msg_hex, &msg_len);
	seed = hex_to_bytes(seed_hex, &seed_len);
	fs = falcon_sign_new();
	if (fs == NULL) {
		fprintf(stderr, "falcon_sign_new failed\n");
		exit(EXIT_FAILURE);
	}
	falcon_sign_set_seed(fs, seed, seed_len, 1);
	if (!falcon_sign_set_private_key(fs, sk, sk_len)) {
		fprintf(stderr, "falcon_sign_set_private_key failed\n");
		exit(EXIT_FAILURE);
	}
	if (!falcon_sign_start(fs, nonce)) {
		fprintf(stderr, "falcon_sign_start failed\n");
		exit(EXIT_FAILURE);
	}
	falcon_sign_update(fs, msg, msg_len);
	sig_max_len = 4096;
	sig = malloc(sig_max_len);
	if (sig == NULL) {
		fprintf(stderr, "allocation failure\n");
		exit(EXIT_FAILURE);
	}
	sig_len = falcon_sign_generate(fs, sig, sig_max_len, comp);
	if (sig_len == 0) {
		fprintf(stderr, "falcon_sign_generate failed\n");
		exit(EXIT_FAILURE);
	}

	print_hex_field("NONCE", nonce, sizeof nonce);
	print_hex_field("SIG", sig, sig_len);

	falcon_sign_free(fs);
	free(sk);
	free(msg);
	free(seed);
	free(sig);
}

int
main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "missing command\n");
		return EXIT_FAILURE;
	}
	if (strcmp(argv[1], "keygen") == 0) {
		if (argc != 5) {
			fprintf(stderr, "usage: keygen <logn> <seed_hex> <comp>\n");
			return EXIT_FAILURE;
		}
		cmd_keygen((unsigned)strtoul(argv[2], NULL, 10), argv[3], atoi(argv[4]));
		return EXIT_SUCCESS;
	}
	if (strcmp(argv[1], "hash_to_point_binary") == 0) {
		if (argc != 5) {
			fprintf(stderr,
				"usage: hash_to_point_binary <logn> <nonce_hex> <msg_hex>\n");
			return EXIT_FAILURE;
		}
		cmd_hash_to_point_binary((unsigned)strtoul(argv[2], NULL, 10),
			argv[3], argv[4]);
		return EXIT_SUCCESS;
	}
	if (strcmp(argv[1], "verify") == 0) {
		if (argc != 6) {
			fprintf(stderr,
				"usage: verify <pk_hex> <nonce_hex> <msg_hex> <sig_hex>\n");
			return EXIT_FAILURE;
		}
		cmd_verify(argv[2], argv[3], argv[4], argv[5]);
		return EXIT_SUCCESS;
	}
	if (strcmp(argv[1], "sign") == 0) {
		if (argc != 6) {
			fprintf(stderr,
				"usage: sign <sk_hex> <msg_hex> <seed_hex> <comp>\n");
			return EXIT_FAILURE;
		}
		cmd_sign(argv[2], argv[3], argv[4], atoi(argv[5]));
		return EXIT_SUCCESS;
	}
	fprintf(stderr, "unknown command: %s\n", argv[1]);
	return EXIT_FAILURE;
}
