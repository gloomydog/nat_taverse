#include "crypto.h"

#include <string.h>
#include <stdio.h>
#include <sodium.h>

/* Argon2id parameters.
 *
 * INTERACTIVE is libsodium's "about 100ms and 64 MiB" setting. MODERATE
 * would be stronger but takes roughly a second and 256 MiB, which is a
 * lot to ask on every connection attempt when the client may retry.
 * INTERACTIVE still turns a single guess into a measurable cost, which is
 * the point. Raise these if your threat model warrants it; both peers
 * must agree. */
#define NT_OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE
#define NT_MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE

/* Fixed salt.
 *
 * A random per-user salt is standard for password storage, where the goal
 * is to stop one rainbow table from breaking every account at once. Here
 * both peers must independently arrive at the same key from the same
 * passphrase with nothing exchanged beforehand, so the salt cannot vary.
 *
 * The tradeoff is that a table precomputed against this salt would work
 * against every user of this program. Argon2id's memory cost is what makes
 * building such a table impractical, and a high-entropy passphrase makes
 * it pointless. */
static const uint8_t NT_SALT[crypto_pwhash_SALTBYTES] = {
    'n','a','t','_','t','r','a','v','e','r','s','e','-','v','1','x'
};

/* Context strings for subkey separation. Eight bytes each, per
 * crypto_kdf. Distinct contexts mean recovering one subkey tells you
 * nothing about the others. */
#define CTX_TOKEN   "nt-token"
#define CTX_RDV     "nt-rdvid"
#define CTX_SEED    "nt-nseed"
#define CTX_CONTENT "nt-ncont"
#define CTX_PSK     "nt-psk-1"

int nt_crypto_init(void) {
    return sodium_init() < 0 ? -1 : 0;
}

/* crypto_kdf refuses to produce fewer than crypto_kdf_BYTES_MIN (16)
 * bytes, and the punch token is 12. Derive a full-length subkey and take
 * the prefix, which is sound: the output is a BLAKE2b stream, so any
 * substring of it is as good as any other. */
static int subkey(uint8_t *out, size_t len, uint64_t id, const char *ctx,
                  const uint8_t master[NT_MASTER_LEN]) {
    if (len >= crypto_kdf_BYTES_MIN && len <= crypto_kdf_BYTES_MAX)
        return crypto_kdf_derive_from_key(out, len, id, ctx, master);

    if (len > crypto_kdf_BYTES_MIN) return -1;   /* not needed here */

        uint8_t tmp[crypto_kdf_BYTES_MIN];
    if (crypto_kdf_derive_from_key(tmp, sizeof(tmp), id, ctx, master) != 0) {
        sodium_memzero(tmp, sizeof(tmp));
        return -1;
    }
    memcpy(out, tmp, len);
    sodium_memzero(tmp, sizeof(tmp));
    return 0;
                  }

                  int nt_derive_keys(const char *passphrase, nt_keys_t *out) {
                      memset(out, 0, sizeof(*out));

                      if (crypto_pwhash(out->master, sizeof(out->master),
                          passphrase, strlen(passphrase),
                                        NT_SALT, NT_OPSLIMIT, NT_MEMLIMIT,
                                        crypto_pwhash_ALG_ARGON2ID13) != 0) {
                          /* The only documented failure is running out of memory. */
                          return -1;
                                        }

                                        if (subkey(out->token, sizeof(out->token), 1, CTX_TOKEN, out->master) != 0 ||
                                            subkey(out->rendezvous, sizeof(out->rendezvous), 2, CTX_RDV, out->master) != 0 ||
                                            subkey(out->nostr_seed, sizeof(out->nostr_seed), 3, CTX_SEED, out->master) != 0 ||
                                            subkey(out->nostr_content_key, sizeof(out->nostr_content_key), 4,
                                                   CTX_CONTENT, out->master) != 0 ||
                                                   subkey(out->psk, sizeof(out->psk), 5, CTX_PSK, out->master) != 0) {
                                            nt_keys_wipe(out);
                                        return -1;
                                                   }
                                                   return 0;
                  }

                  void nt_keys_wipe(nt_keys_t *k) {
                      sodium_memzero(k, sizeof(*k));
                  }

                  int nt_equal(const void *a, const void *b, size_t len) {
                      return sodium_memcmp(a, b, len) == 0;
                  }

                  void nt_random(void *buf, size_t len) {
                      randombytes_buf(buf, len);
                  }

                  void nt_wipe(void *buf, size_t len) {
                      sodium_memzero(buf, len);
                  }

                  /* Exactly 256 words, so one random byte selects one word with no modulo
                   * bias and each word carries exactly 8 bits. Sixteen words therefore
                   * carry exactly 128 bits, which is the number quoted in the header. */
                  static const char *WORDS[] = {
                      "acorn","amber","anchor","apple","arrow","atlas","autumn","badge",
                      "bamboo","basin","beacon","birch","bishop","bloom","bonus","branch",
                      "bridge","bronze","cactus","candle","canyon","cargo","cedar","chalk",
                      "cherry","chorus","cinder","clover","cobalt","comet","copper","coral",
                      "cosmos","cotton","cradle","crane","crater","crimson","crystal","dahlia",
                      "damper","dapper","dawn","delta","denim","desert","diamond","dial",
                      "dolphin","domino","drift","dune","eagle","eclipse","ember","emerald",
                      "engine","escape","ether","fable","falcon","fathom","feather","fennel",
                      "ferry","fiber","fiddle","fjord","flame","flint","forest","fossil",
                      "fountain","fresco","frost","gable","galaxy","garnet","gauge","ginger",
                      "glacier","glider","granite","gravel","grotto","harbor","harvest","hazel",
                      "hearth","helix","hollow","honey","hunter","indigo","ivory","jade",
                      "jasmine","jetty","jungle","kernel","kettle","keystone","lagoon","lantern",
                      "lattice","legend","lichen","lilac","linen","lodge","lotus","lumber",
                      "magnet","mahogany","mantle","maple","marble","marsh","meadow","mercury",
                      "meteor","mineral","mirror","mist","monsoon","mosaic","moss","nectar",
                      "nickel","nomad","nutmeg","oasis","obsidian","ocean","onyx","opal",
                      "orbit","orchid","otter","oxide","paddle","palace","pantry","papaya",
                      "pastel","pebble","pepper","phantom","pigment","pillar","pine","pioneer",
                      "pivot","plateau","plume","pollen","poplar","portal","prairie","prism",
                      "puzzle","quarry","quartz","quiver","radar","rafter","ranger","raven",
                      "reef","relay","ribbon","ridge","ripple","river","rocket","rosemary",
                      "rustic","saffron","sage","salmon","sandal","sapphire","satin","savory",
                      "scarlet","sculpt","seagull","sequoia","shadow","shale","shelter","sierra",
                      "signal","silver","siren","slate","sleet","socket","solar","sonnet",
                      "spark","sphere","spiral","spruce","stellar","stencil","stone","storm",
                      "stream","summit","sundial","sunset","syrup","tabby","talon","tandem",
                      "tangent","tapestry","teal","tempo","terrain","thicket","thistle","thunder",
                      "timber","topaz","torch","totem","trellis","tribute","trident","trolley",
                      "tulip","tundra","turbine","turquoise","umber","vanilla","velvet","vertex",
                      "vessel","vineyard","violet","viper","vista","walnut","wander","wavelet",
                      "whisper","willow","window","winter","wombat","yarrow","zenith","zephyr",
                  };
                  #define NWORDS (sizeof(WORDS) / sizeof(WORDS[0]))

                  void nt_generate_secret(char *buf, size_t buflen) {
                      uint8_t r[16];
                      randombytes_buf(r, sizeof(r));

                      buf[0] = '\0';
                      size_t used = 0;
                      for (size_t i = 0; i < sizeof(r); i++) {
                          int n = snprintf(buf + used, buflen - used, "%s%s",
                                           i ? "-" : "", WORDS[r[i]]);
                          if (n < 0 || (size_t)n >= buflen - used) break;
                          used += (size_t)n;
                      }
                      sodium_memzero(r, sizeof(r));
                  }
