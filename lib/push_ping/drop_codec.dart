// Push ping (portnook fork): not part of upstream Moonfin.
//
// Opens a drop: the small file portnook keeps for this device on a storage
// host. Only this device can read it and only portnook can have written it.
//
//   "PNP1" (4) | ephemeral X25519 public key (32) | nonce (16) | ciphertext |
//   tag (32) | Ed25519 signature (64)
//
// * Signature: Ed25519 by portnook's signing key (pinned at registration)
//   over everything before it.
// * Keys: X25519(device key, ephemeral key), then HKDF-SHA256 with salt =
//   nonce and info = "portnook push v1" || ephemeral pub || device pub,
//   64 bytes: encryption key, MAC key.
// * Tag: HMAC-SHA256(MAC key, everything before it).
// * Plaintext: block i of the keystream is HMAC-SHA256(encryption key,
//   nonce || i as 4 byte big endian), XORed with the ciphertext.
//
// The same format is built by portnook (agent/app/pushcrypto.py) and checked
// with the same test vector (test/push_ping/push_drop.json).
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

class DropException implements Exception {
  DropException(this.message);
  final String message;
  @override
  String toString() => 'DropException: $message';
}

/// The content of a drop.
class DropContent {
  DropContent({required this.url, required this.seq, required this.ts, required this.cert});

  /// Where the server answers now, e.g. `https://jf.example.ch:51234`.
  final String url;

  /// Grows with every drop portnook writes for this device.
  final int seq;
  final int ts;

  /// `sha256/<base64>` of a pinned certificate, empty for system trust.
  final String cert;

  static DropContent fromJson(Map<String, dynamic> json) {
    final url = json['url'];
    final seq = json['seq'];
    if (url is! String || seq is! int || json['v'] != 1) {
      throw DropException('unexpected content');
    }
    return DropContent(
      url: url,
      seq: seq,
      ts: json['ts'] is int ? json['ts'] as int : 0,
      cert: json['cert'] is String ? json['cert'] as String : '',
    );
  }
}

class DropCodec {
  static final _magic = ascii.encode('PNP1');
  static final _info = ascii.encode('portnook push v1');
  static const _keyLen = 32;
  static const _nonceLen = 16;
  static const _tagLen = 32;
  static const _sigLen = 64;
  static const _headerLen = 4 + _keyLen + _nonceLen;

  static final _hmac = Hmac.sha256();

  /// A new device key: the 32 byte X25519 private key (seed).
  static Future<Uint8List> newDeviceKey() async {
    final pair = await X25519().newKeyPair();
    return Uint8List.fromList(await pair.extractPrivateKeyBytes());
  }

  /// The 32 byte public key of the device key [seed].
  static Future<Uint8List> publicOf(List<int> seed) async {
    final pair = await X25519().newKeyPairFromSeed(seed);
    return Uint8List.fromList((await pair.extractPublicKey()).bytes);
  }

  static Future<List<int>> _mac(List<int> key, List<int> data) async =>
      (await _hmac.calculateMac(data, secretKey: SecretKey(key))).bytes;

  static Future<List<int>> hkdf(
    List<int> ikm,
    List<int> salt,
    List<int> info,
    int length,
  ) async {
    final prk = await _mac(salt, ikm);
    final out = <int>[];
    var block = <int>[];
    var counter = 1;
    while (out.length < length) {
      block = await _mac(prk, [...block, ...info, counter]);
      out.addAll(block);
      counter++;
    }
    return out.sublist(0, length);
  }

  static Future<List<int>> _keystreamXor(
    List<int> key,
    List<int> nonce,
    List<int> data,
  ) async {
    final out = <int>[];
    for (var i = 0; i < data.length; i += 32) {
      final n = i ~/ 32;
      final block = await _mac(key, [
        ...nonce,
        (n >> 24) & 0xff,
        (n >> 16) & 0xff,
        (n >> 8) & 0xff,
        n & 0xff,
      ]);
      final end = i + 32 < data.length ? i + 32 : data.length;
      for (var j = i; j < end; j++) {
        out.add(data[j] ^ block[j - i]);
      }
    }
    return out;
  }

  static bool _same(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  /// The plaintext of [drop] for the device key [seed]; throws
  /// [DropException] when it is not from the holder of [signPub].
  static Future<List<int>> openRaw(
    List<int> drop,
    List<int> seed,
    List<int> signPub,
  ) async {
    if (drop.length < _headerLen + _tagLen + _sigLen ||
        !_same(drop.sublist(0, 4), _magic)) {
      throw DropException('not a drop');
    }
    final body = drop.sublist(0, drop.length - _sigLen);
    final sig = drop.sublist(drop.length - _sigLen);
    final ok = await Ed25519().verify(
      body,
      signature: Signature(
        sig,
        publicKey: SimplePublicKey(signPub, type: KeyPairType.ed25519),
      ),
    );
    if (!ok) throw DropException('bad signature');
    final ephPub = drop.sublist(4, 4 + _keyLen);
    final nonce = drop.sublist(4 + _keyLen, _headerLen);
    final pair = await X25519().newKeyPairFromSeed(seed);
    final devicePub = (await pair.extractPublicKey()).bytes;
    final shared = await (await X25519().sharedSecretKey(
      keyPair: pair,
      remotePublicKey: SimplePublicKey(ephPub, type: KeyPairType.x25519),
    )).extractBytes();
    if (shared.every((b) => b == 0)) throw DropException('key agreement');
    final okm = await hkdf(shared, nonce, [..._info, ...ephPub, ...devicePub], 64);
    final tag = await _mac(okm.sublist(32), body.sublist(0, body.length - _tagLen));
    if (!_same(tag, body.sublist(body.length - _tagLen))) {
      throw DropException('bad tag');
    }
    return _keystreamXor(
      okm.sublist(0, 32),
      nonce,
      body.sublist(_headerLen, body.length - _tagLen),
    );
  }

  static Future<DropContent> open(
    List<int> drop,
    List<int> seed,
    List<int> signPub,
  ) async {
    final plain = await openRaw(drop, seed, signPub);
    final Object? json;
    try {
      json = jsonDecode(utf8.decode(plain));
    } catch (_) {
      throw DropException('content not JSON');
    }
    if (json is! Map<String, dynamic>) throw DropException('content not an object');
    return DropContent.fromJson(json);
  }

  static Uint8List fromHex(String hex) {
    final out = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(hex.substring(2 * i, 2 * i + 2), radix: 16);
    }
    return out;
  }

  static String toHex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
