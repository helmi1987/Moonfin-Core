// Push ping gate (portnook fork): not part of upstream Moonfin.
//
// portnook's neutral sign-in page (`<target>/_pn/`) in a web view, for a
// server whose gate lets only set-up devices through. The page shows a code
// to confirm on a device already signed in (or user and password) and hands
// its result to the app through the `PnBridge` channel.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

class PushPingSignInPage extends StatefulWidget {
  const PushPingSignInPage({super.key, required this.base});

  /// `https://host:port` of the server behind the gate.
  final String base;

  @override
  State<PushPingSignInPage> createState() => _PushPingSignInPageState();
}

class _PushPingSignInPageState extends State<PushPingSignInPage> {
  late final WebViewController _controller;
  bool _done = false;

  @override
  void initState() {
    super.initState();
    final page = Uri.parse('${widget.base}/_pn/').replace(
      queryParameters: {
        'client': 'Moonfin',
        'device': 'Moonfin ${Platform.operatingSystem}',
        'version': '1',
      },
    );
    _controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setBackgroundColor(Colors.black)
      ..addJavaScriptChannel('PnBridge', onMessageReceived: _onResult)
      ..loadRequest(page);
  }

  void _onResult(JavaScriptMessage message) {
    if (_done) return;
    try {
      final result = jsonDecode(message.message);
      if (result is Map<String, dynamic> && result['token'] is String) {
        _done = true;
        Navigator.of(context).pop(result);
      }
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.close),
          onPressed: () => Navigator.of(context).pop(),
        ),
        title: Text(Uri.parse(widget.base).host),
      ),
      body: SafeArea(child: WebViewWidget(controller: _controller)),
    );
  }
}
