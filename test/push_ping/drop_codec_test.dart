// Push ping (portnook fork): the drop format against portnook's test vector.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:moonfin/push_ping/drop_codec.dart';

/// The raw 32 byte key of a PKCS#8 PEM X25519 private key.
List<int> rawPrivate(String pem) {
  final b64 = pem.split('\n').where((l) => l.isNotEmpty && !l.startsWith('-----')).join();
  final der = base64.decode(b64);
  return der.sublist(der.length - 32);
}

void main() {
  final v = jsonDecode(File('test/push_ping/push_drop.json').readAsStringSync()) as Map<String, dynamic>;
  final drop = DropCodec.fromHex(v['drop'] as String);
  final seed = rawPrivate(v['device_key_pem'] as String);
  final signPub = DropCodec.fromHex(v['sign_pub'] as String);

  test('opens the vector', () async {
    final c = await DropCodec.open(drop, seed, signPub);
    expect(c.url, 'https://203.0.113.7:51234');
    expect(c.seq, 7);
  });

  test('device public key matches', () async {
    expect(DropCodec.toHex(await DropCodec.publicOf(seed)), v['device_pub']);
  });

  test('a changed byte is refused', () async {
    final bad = List<int>.from(drop);
    bad[60] ^= 1;
    expect(() => DropCodec.open(bad, seed, signPub), throwsA(isA<DropException>()));
  });

  test('another device key is refused', () async {
    final other = await DropCodec.newDeviceKey();
    expect(() => DropCodec.open(drop, other, signPub), throwsA(isA<DropException>()));
  });
}
