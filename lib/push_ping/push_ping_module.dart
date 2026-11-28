// Push ping (portnook fork): not part of upstream Moonfin.
//
// Wires push ping into the app, from `registerEntryRedirect`:
//
// * EntryRedirect asks this device's file first when it follows a server.
// * Firebase (Android only) starts with the options portnook handed over at
//   registration, only in a build without its own Firebase configuration
//   (the fork's test builds). Its push token goes to portnook.
// * A push ("t": "refresh"), a return to the app and the start of a session
//   make the app read its files again.
import 'dart:async';
import 'dart:isolate';
import 'dart:ui' show IsolateNameServer;

import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:get_it/get_it.dart';

import '../entry_redirect/entry_redirect.dart';
import '../util/platform_detection.dart';
import 'push_ping.dart';

const _portName = 'moonfin_push_ping';

/// Called from upstream's FCM background handler (`push ping` hook): a
/// refresh push that arrives while the app runs in the background is passed
/// to the app's own isolate, which reads the files again.
void pushPingBackground(RemoteMessage message) {
  if (message.data['t'] != 'refresh') return;
  IsolateNameServer.lookupPortByName(_portName)?.send('refresh');
}

Future<void> registerPushPing(EntryRedirect redirect) async {
  final getIt = GetIt.instance;
  if (getIt.isRegistered<PushPing>()) return;
  final ping = PushPing(
    platform: PlatformDetection.isAndroid
        ? 'android'
        : PlatformDetection.isAppleTV
        ? 'tvos'
        : PlatformDetection.isIOS
        ? 'ios'
        : 'other',
  );
  await ping.init();
  getIt.registerSingleton<PushPing>(ping);
  redirect.pushPing = ping;
  final messaging = _PushPingMessaging(ping, redirect);
  ping.changed.listen((_) => unawaited(messaging.start()));
  unawaited(messaging.start());
}

class _PushPingMessaging with WidgetsBindingObserver {
  _PushPingMessaging(this.ping, this.redirect);

  final PushPing ping;
  final EntryRedirect redirect;
  bool _started = false;
  bool _observing = false;
  DateTime _lastRefresh = DateTime.fromMillisecondsSinceEpoch(0);

  void _refresh() {
    // Several triggers at once (resume + push) read the files once.
    final now = DateTime.now();
    if (now.difference(_lastRefresh) < const Duration(seconds: 5)) return;
    _lastRefresh = now;
    unawaited(redirect.followAllEntryAddresses());
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed && ping.records.isNotEmpty) _refresh();
  }

  Future<void> start() async {
    if (!_observing && ping.records.isNotEmpty) {
      _observing = true;
      WidgetsBinding.instance.addObserver(this);
      final port = ReceivePort();
      IsolateNameServer.removePortNameMapping(_portName);
      IsolateNameServer.registerPortWithName(port.sendPort, _portName);
      port.listen((_) => _refresh());
    }
    if (_started || !PlatformDetection.isAndroid) return;
    final fcm = ping.records.map((r) => r.fcm).whereType<Map<String, String>>().firstOrNull;
    if (fcm == null) return;
    _started = true;
    try {
      if (Firebase.apps.isEmpty) {
        await Firebase.initializeApp(
          options: FirebaseOptions(
            apiKey: fcm['api_key']!,
            appId: fcm['app_id']!,
            messagingSenderId: fcm['sender_id']!,
            projectId: fcm['project_id']!,
          ),
        );
      } else if (Firebase.app().options.projectId != fcm['project_id']) {
        // A build with its own Firebase project: its tokens belong there and
        // portnook can't reach them.
        debugPrint('PushPing: Firebase belongs to another project, no push');
        return;
      }
      final messaging = FirebaseMessaging.instance;
      messaging.onTokenRefresh.listen((t) => unawaited(ping.setPushToken(t)));
      FirebaseMessaging.onMessage.listen((m) {
        if (m.data['t'] == 'refresh') _refresh();
      });
      final token = await messaging.getToken();
      if (token != null) await ping.setPushToken(token);
      debugPrint('PushPing: push ready');
    } catch (e) {
      _started = false;
      debugPrint('PushPing: Firebase start failed: $e');
    }
  }
}
