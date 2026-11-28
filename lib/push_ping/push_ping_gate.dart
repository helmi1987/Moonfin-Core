// Push ping gate (portnook fork): not part of upstream Moonfin.
//
// portnook can let only set-up devices through to the media server (its
// "gate", checked by the reverse proxy before every request). A set-up device
// proves itself with the header `X-PN-Gate: v1.<device id>.<unix time>.<hmac>`
// (HMAC-SHA256 with the gate key portnook handed out at registration).
//
// [PushPing] installs the lookup; every request the app makes to a server it
// registered with carries the header: dart:io requests (data, images,
// websockets) through the app's HttpOverrides, the players through their
// stream headers. Requests to any other host never get it.
import 'dart:convert';

import 'package:crypto/crypto.dart';

class PushPingGate {
  PushPingGate._();

  static const headerName = 'X-PN-Gate';

  static String? Function(Uri uri)? _lookup;

  /// Set by [PushPing]: the header value for a request to [uri], or null.
  static void install(String? Function(Uri uri) lookup) => _lookup = lookup;

  /// The gate header for a request to [url]; empty for every other host.
  static Map<String, String> headersFor(String url) {
    final lookup = _lookup;
    if (lookup == null) return const {};
    final uri = Uri.tryParse(url);
    if (uri == null || !uri.hasAuthority) return const {};
    final value = lookup(uri);
    return value == null ? const {} : {headerName: value};
  }

  /// `v1.<device id>.<time>.<hmac>`, as portnook checks it (app/pushgate.py).
  static String sign(String deviceId, String keyHex, int unixSeconds) {
    final msg = 'v1.$deviceId.$unixSeconds';
    final key = [
      for (var i = 0; i + 1 < keyHex.length; i += 2)
        int.parse(keyHex.substring(i, i + 2), radix: 16),
    ];
    return '$msg.${Hmac(sha256, key).convert(utf8.encode(msg))}';
  }

  /// `scheme://host:port` of [uri], the key requests are matched by.
  static String originOf(Uri uri) =>
      '${uri.scheme}://${uri.host.toLowerCase()}:${uri.port}';
}
