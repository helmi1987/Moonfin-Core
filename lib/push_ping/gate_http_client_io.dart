// Push ping gate (portnook fork): not part of upstream Moonfin.
//
// An [HttpClient] that adds the gate header (push_ping_gate.dart) to every
// request it opens to a server set up with portnook. The app's HttpOverrides
// wrap each client in it, so Dio, images and websockets all carry it.
import 'dart:io';

import 'push_ping_gate.dart';

class GatedHttpClient implements HttpClient {
  GatedHttpClient(this._inner);

  final HttpClient _inner;

  Future<HttpClientRequest> _gated(Future<HttpClientRequest> opened) =>
      opened.then((request) {
        PushPingGate.headersFor(request.uri.toString()).forEach(
          request.headers.set,
        );
        return request;
      });

  @override
  Duration get idleTimeout => _inner.idleTimeout;
  @override
  set idleTimeout(Duration value) => _inner.idleTimeout = value;

  @override
  Duration? get connectionTimeout => _inner.connectionTimeout;
  @override
  set connectionTimeout(Duration? value) => _inner.connectionTimeout = value;

  @override
  int? get maxConnectionsPerHost => _inner.maxConnectionsPerHost;
  @override
  set maxConnectionsPerHost(int? value) => _inner.maxConnectionsPerHost = value;

  @override
  bool get autoUncompress => _inner.autoUncompress;
  @override
  set autoUncompress(bool value) => _inner.autoUncompress = value;

  @override
  String? get userAgent => _inner.userAgent;
  @override
  set userAgent(String? value) => _inner.userAgent = value;

  @override
  set authenticate(
    Future<bool> Function(Uri url, String scheme, String? realm)? f,
  ) => _inner.authenticate = f;

  @override
  set connectionFactory(
    Future<ConnectionTask<Socket>> Function(
      Uri url,
      String? proxyHost,
      int? proxyPort,
    )?
    f,
  ) => _inner.connectionFactory = f;

  @override
  set findProxy(String Function(Uri url)? f) => _inner.findProxy = f;

  @override
  set authenticateProxy(
    Future<bool> Function(String host, int port, String scheme, String? realm)?
    f,
  ) => _inner.authenticateProxy = f;

  @override
  set badCertificateCallback(
    bool Function(X509Certificate cert, String host, int port)? callback,
  ) => _inner.badCertificateCallback = callback;

  @override
  set keyLog(Function(String line)? callback) => _inner.keyLog = callback;

  @override
  Future<HttpClientRequest> open(
    String method,
    String host,
    int port,
    String path,
  ) => _gated(_inner.open(method, host, port, path));

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) =>
      _gated(_inner.openUrl(method, url));

  @override
  Future<HttpClientRequest> get(String host, int port, String path) =>
      _gated(_inner.get(host, port, path));

  @override
  Future<HttpClientRequest> getUrl(Uri url) => _gated(_inner.getUrl(url));

  @override
  Future<HttpClientRequest> post(String host, int port, String path) =>
      _gated(_inner.post(host, port, path));

  @override
  Future<HttpClientRequest> postUrl(Uri url) => _gated(_inner.postUrl(url));

  @override
  Future<HttpClientRequest> put(String host, int port, String path) =>
      _gated(_inner.put(host, port, path));

  @override
  Future<HttpClientRequest> putUrl(Uri url) => _gated(_inner.putUrl(url));

  @override
  Future<HttpClientRequest> delete(String host, int port, String path) =>
      _gated(_inner.delete(host, port, path));

  @override
  Future<HttpClientRequest> deleteUrl(Uri url) =>
      _gated(_inner.deleteUrl(url));

  @override
  Future<HttpClientRequest> patch(String host, int port, String path) =>
      _gated(_inner.patch(host, port, path));

  @override
  Future<HttpClientRequest> patchUrl(Uri url) => _gated(_inner.patchUrl(url));

  @override
  Future<HttpClientRequest> head(String host, int port, String path) =>
      _gated(_inner.head(host, port, path));

  @override
  Future<HttpClientRequest> headUrl(Uri url) => _gated(_inner.headUrl(url));

  @override
  void addCredentials(
    Uri url,
    String realm,
    HttpClientCredentials credentials,
  ) => _inner.addCredentials(url, realm, credentials);

  @override
  void addProxyCredentials(
    String host,
    int port,
    String realm,
    HttpClientCredentials credentials,
  ) => _inner.addProxyCredentials(host, port, realm, credentials);

  @override
  void close({bool force = false}) => _inner.close(force: force);
}
