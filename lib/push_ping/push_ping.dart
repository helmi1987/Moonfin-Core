// Push ping (portnook fork): not part of upstream Moonfin.
//
// A server added through a portnook entry address can tell this device its
// current address privately: portnook keeps one sealed file per device on a
// storage host (see drop_codec.dart) and pings the device by push when it
// changed. This service
//
// * registers the device once after sign-in (`<server>/_pn/register`, with
//   the session's access token, which portnook checks against the server),
// * reads the file and hands its address to EntryRedirect, which checks it
//   (same server `Id`) and saves it like a followed redirect,
// * passes a new push token to portnook (`<server>/_pn/device`).
//
// Nothing happens for a server whose address has no `/_pn/hello`.
//
// Gate (portnook's "Türsteher"): portnook can let only set-up devices through.
// The gate key from the registration signs the header every request to that
// server carries (push_ping_gate.dart). A server whose gate is on can't be
// added before that, so [prepareGate] signs in on portnook's page first and
// registers under the target's address; the record moves to the server once
// it is saved ([adopt]).
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import 'drop_codec.dart';
import 'push_ping_gate.dart';

/// What this device keeps for one server.
class PushPingRecord {
  PushPingRecord({
    required this.deviceId,
    required this.dropUrl,
    required this.signPub,
    this.seq = 0,
    this.pushToken = '',
    this.fcm,
  });

  final String deviceId;
  String dropUrl;

  /// portnook's signing key, pinned at registration (hex).
  final String signPub;
  int seq;
  String pushToken;

  /// Firebase options of portnook's project (`api_key`, `app_id`,
  /// `project_id`, `sender_id`), when portnook has them.
  Map<String, String>? fcm;

  Map<String, dynamic> toJson() => {
    'device_id': deviceId,
    'drop_url': dropUrl,
    'sign_pub': signPub,
    'seq': seq,
    'push_token': pushToken,
    if (fcm != null) 'fcm': fcm,
  };

  static PushPingRecord? fromJson(Object? j) {
    if (j is! Map) return null;
    final id = j['device_id'], drop = j['drop_url'], pub = j['sign_pub'];
    if (id is! String || drop is! String || pub is! String) return null;
    final fcm = j['fcm'];
    return PushPingRecord(
      deviceId: id,
      dropUrl: drop,
      signPub: pub,
      seq: j['seq'] is int ? j['seq'] as int : 0,
      pushToken: j['push_token'] is String ? j['push_token'] as String : '',
      fcm: fcm is Map ? fcm.map((k, v) => MapEntry('$k', '$v')) : null,
    );
  }
}

class PushPing {
  PushPing({http.Client? client, FlutterSecureStorage? secure, this.platform = 'android'})
    : _http = client ?? http.Client(),
      _secure = secure ?? const FlutterSecureStorage();

  final http.Client _http;
  final FlutterSecureStorage _secure;
  final String platform;

  static const _prefsKey = 'push_ping_json';
  static const _seedPrefix = 'push_ping_seed_';
  static const _gatePrefix = 'push_ping_gate_';

  /// Shows portnook's sign-in page at [base] (`<target>/_pn/`) and returns
  /// its result (`token`, `user_id`, `server_id`, ...), or null when closed.
  /// Set by the module; without it a gated server can't be added.
  Future<Map<String, dynamic>?> Function(String base)? signIn;

  /// Gate keys by server (secure storage), and which server an address is.
  final _gateKeys = <String, String>{};
  final _origins = <String, String>{};
  static const _timeout = Duration(seconds: 6);

  final _records = <String, PushPingRecord>{};

  /// Access tokens of the current sessions, in memory only, so a push token
  /// that arrives later can still be passed on.
  final _sessions = <String, (String baseUrl, String token)>{};

  /// The push token of this device (Firebase), once known.
  String _pushToken = '';

  /// Runs when a server's record changed (FCM options arrived).
  final _changed = StreamController<void>.broadcast();
  Stream<void> get changed => _changed.stream;

  Iterable<PushPingRecord> get records => _records.values;
  PushPingRecord? recordOf(String serverId) => _records[serverId];

  Future<void> init() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString(_prefsKey);
      if (raw == null) return;
      final json = jsonDecode(raw);
      if (json is! Map) return;
      json.forEach((k, v) {
        final r = PushPingRecord.fromJson(v);
        if (r != null) _records['$k'] = r;
      });
      for (final id in _records.keys) {
        final key = await _secure.read(key: '$_gatePrefix$id');
        if (key != null && key.length == 64) _gateKeys[id] = key;
      }
    } catch (e) {
      debugPrint('PushPing: load failed: $e');
    }
    PushPingGate.install(_gateHeader);
  }

  /// [serverId] is reached at [address] now: requests there carry its gate
  /// header.
  void noteAddress(String serverId, String address) {
    final uri = Uri.tryParse(address);
    if (uri == null || !uri.hasAuthority || !_records.containsKey(serverId)) return;
    _origins.removeWhere((_, id) => id == serverId);
    _origins[PushPingGate.originOf(uri)] = serverId;
  }

  String? _gateHeader(Uri uri) {
    final id = _origins[PushPingGate.originOf(uri)];
    final key = id == null ? null : _gateKeys[id];
    final rec = id == null ? null : _records[id];
    if (key == null || rec == null) return null;
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return PushPingGate.sign(rec.deviceId, key, now);
  }

  Future<void> _saveGateKey(String serverId, Object? key) async {
    if (key is! String || !RegExp(r'^[0-9a-f]{64}$').hasMatch(key)) return;
    if (_gateKeys[serverId] == key) return;
    _gateKeys[serverId] = key;
    await _secure.write(key: '$_gatePrefix$serverId', value: key);
  }

  /// Before adding the server at [address]: when portnook's gate is on there
  /// and this device has no key for it yet, sign in on portnook's page and
  /// register, so the server can be reached. Quietly does nothing elsewhere.
  Future<void> prepareGate(String address) async {
    final ui = signIn;
    if (ui == null) return;
    try {
      // the entry address answers through its redirect: the target is where
      // the page and the server are, so the redirects are followed here
      var url = Uri.parse('${_base(address)}/_pn/hello');
      http.Response? res;
      for (var i = 0; i < 5 && res == null; i++) {
        final req = http.Request('GET', url)..followRedirects = false;
        final r = await http.Response.fromStream(await _http.send(req).timeout(_timeout));
        final loc = r.headers['location'];
        if (const [301, 302, 303, 307, 308].contains(r.statusCode) && loc != null) {
          url = url.resolve(loc);
        } else {
          res = r;
        }
      }
      if (res == null || res.statusCode != 200) return;
      final json = jsonDecode(res.body);
      if (json is! Map || json['ok'] != true || json['gate'] != true) return;
      final origin = PushPingGate.originOf(url);
      final known = _origins[origin];
      if (known != null && _gateKeys[known] != null) return;
      final base = origin.replaceFirst(RegExp(r':443$'), '');
      final pendingId = 'pending:$origin';
      final result = await ui(base);
      final token = result?['token'];
      if (token is! String || token.isEmpty) return;
      final rec = await _register(pendingId, base, token);
      if (rec != null) noteAddress(pendingId, base);
    } catch (e) {
      debugPrint('PushPing: gate sign-in failed: $e');
    }
  }

  /// The server registered by [prepareGate] at [address] was saved as
  /// [serverId]: its record and keys move there.
  Future<void> adopt(String serverId, String address) async {
    final uri = Uri.tryParse(address);
    if (uri == null || !uri.hasAuthority) return;
    final pendingId = 'pending:${PushPingGate.originOf(uri)}';
    final rec = _records.remove(pendingId);
    if (rec == null || _records.containsKey(serverId)) return;
    _records[serverId] = rec;
    final seed = await _secure.read(key: '$_seedPrefix$pendingId');
    if (seed != null) await _secure.write(key: '$_seedPrefix$serverId', value: seed);
    await _secure.delete(key: '$_seedPrefix$pendingId');
    final key = _gateKeys.remove(pendingId);
    await _secure.delete(key: '$_gatePrefix$pendingId');
    if (key != null) await _saveGateKey(serverId, key);
    await _save();
    noteAddress(serverId, address);
    debugPrint('PushPing: registration moved to the saved server');
    _changed.add(null);
  }

  Future<void> _save() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      _prefsKey,
      jsonEncode(_records.map((k, v) => MapEntry(k, v.toJson()))),
    );
  }

  static String _base(String url) => url.endsWith('/') ? url.substring(0, url.length - 1) : url;

  Future<Map<String, dynamic>?> _post(String url, Map<String, dynamic> body) async {
    final res = await _http
        .post(Uri.parse(url), headers: {'Content-Type': 'application/json'}, body: jsonEncode(body))
        .timeout(_timeout);
    if (res.statusCode != 200) {
      debugPrint('PushPing: $url answered ${res.statusCode}');
      return null;
    }
    final json = jsonDecode(res.body);
    return json is Map<String, dynamic> ? json : null;
  }

  Future<bool> _hasPushPing(String base) async {
    try {
      final res = await _http.get(Uri.parse('$base/_pn/hello')).timeout(_timeout);
      if (res.statusCode != 200) return false;
      final json = jsonDecode(res.body);
      return json is Map && json['ok'] == true;
    } catch (_) {
      return false;
    }
  }

  static Map<String, String>? _fcmOf(Map<String, dynamic> answer) {
    final f = answer['fcm'];
    if (f is! Map) return null;
    final m = f.map((k, v) => MapEntry('$k', '$v'));
    return ['api_key', 'app_id', 'project_id', 'sender_id'].every((k) => (m[k] ?? '').isNotEmpty) ? m : null;
  }

  /// After a sign-in to [serverId] at [baseUrl] with [token]: register this
  /// device once, or pass a new push token on.
  Future<void> afterLogin(String serverId, String baseUrl, String token) async {
    final base = _base(baseUrl);
    _sessions[serverId] = (base, token);
    try {
      final rec = _records[serverId];
      if (rec != null) {
        noteAddress(serverId, base);
        if ((_pushToken.isNotEmpty && rec.pushToken != _pushToken) ||
            rec.fcm == null ||
            _gateKeys[serverId] == null) {
          await _update(serverId, rec, base, token);
        }
        return;
      }
      if (!await _hasPushPing(base)) return;
      if (await _register(serverId, base, token) != null) noteAddress(serverId, base);
    } catch (e) {
      debugPrint('PushPing: sign-in hook failed: $e');
    }
  }

  Future<PushPingRecord?> _register(String serverId, String base, String token) async {
    final seed = await DropCodec.newDeviceKey();
    final answer = await _post('$base/_pn/register', {
      'token': token,
      'device_pub': DropCodec.toHex(await DropCodec.publicOf(seed)),
      'push_token': _pushToken,
      'platform': platform,
      'name': 'Moonfin ${Platform.operatingSystem}',
    });
    final id = answer?['device_id'], drop = answer?['drop_url'], pub = answer?['sign_pub'];
    if (id is! String || drop is! String || pub is! String || pub.length != 64) return null;
    await _secure.write(key: '$_seedPrefix$serverId', value: DropCodec.toHex(seed));
    await _saveGateKey(serverId, answer!['gate_key']);
    _records[serverId] = PushPingRecord(
      deviceId: id,
      dropUrl: drop,
      signPub: pub,
      seq: answer!['seq'] is int ? answer['seq'] as int : 0,
      pushToken: _pushToken,
      fcm: _fcmOf(answer),
    );
    await _save();
    debugPrint('PushPing: registered as $id');
    _changed.add(null);
    return _records[serverId];
  }

  Future<void> _update(String serverId, PushPingRecord rec, String base, String token) async {
    final answer = await _post('$base/_pn/device', {
      'token': token,
      'device_id': rec.deviceId,
      if (_pushToken.isNotEmpty) 'push_token': _pushToken,
    });
    if (answer == null) return;
    await _saveGateKey(serverId, answer['gate_key']);
    rec.pushToken = _pushToken;
    if (answer['drop_url'] is String && (answer['drop_url'] as String).isNotEmpty) {
      rec.dropUrl = answer['drop_url'] as String;
    }
    final hadFcm = rec.fcm != null;
    rec.fcm = _fcmOf(answer) ?? rec.fcm;
    await _save();
    if (!hadFcm && rec.fcm != null) _changed.add(null);
  }

  /// A new push token of this device: passed on to every server with a
  /// session now; the others get it at their next sign-in.
  Future<void> setPushToken(String token) async {
    if (token.isEmpty || token == _pushToken) return;
    _pushToken = token;
    for (final e in _records.entries) {
      final s = _sessions[e.key];
      if (s != null && e.value.pushToken != token) {
        try {
          await _update(e.key, e.value, s.$1, s.$2);
        } catch (e) {
          debugPrint('PushPing: push token update failed: $e');
        }
      }
    }
  }

  /// The address in this device's file for [serverId], or null when there is
  /// none or it doesn't verify. An older file than the last one read is
  /// ignored, so a stale copy can't send the app back.
  Future<String?> addressOf(String serverId) async {
    final rec = _records[serverId];
    if (rec == null || rec.dropUrl.isEmpty) return null;
    try {
      final seedHex = await _secure.read(key: '$_seedPrefix$serverId');
      if (seedHex == null) return null;
      final res = await _http
          .get(Uri.parse(rec.dropUrl), headers: {'Cache-Control': 'no-cache'})
          .timeout(_timeout);
      if (res.statusCode != 200) return null;
      final c = await DropCodec.open(
        res.bodyBytes,
        DropCodec.fromHex(seedHex),
        DropCodec.fromHex(rec.signPub),
      );
      if (c.seq < rec.seq) return null;
      if (c.seq != rec.seq) {
        rec.seq = c.seq;
        await _save();
      }
      final uri = Uri.tryParse(c.url);
      if (uri == null || uri.scheme != 'https' || uri.host.isEmpty) return null;
      // the address is checked with a probe before it is used: it needs the
      // gate header too
      _origins.putIfAbsent(PushPingGate.originOf(uri), () => serverId);
      return _base(c.url);
    } catch (e) {
      debugPrint('PushPing: file of $serverId not read: $e');
      return null;
    }
  }

  /// Forget [serverId] (server removed).
  Future<void> forget(String serverId) async {
    _sessions.remove(serverId);
    if (_records.remove(serverId) == null) return;
    _origins.removeWhere((_, id) => id == serverId);
    _gateKeys.remove(serverId);
    await _save();
    try {
      await _secure.delete(key: '$_seedPrefix$serverId');
      await _secure.delete(key: '$_gatePrefix$serverId');
    } catch (_) {}
  }
}
