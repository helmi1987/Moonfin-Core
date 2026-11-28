// Push ping gate (portnook fork): the header must match portnook's check
// (agent/app/pushgate.py, same values there).
import 'package:flutter_test/flutter_test.dart';
import 'package:moonfin/push_ping/push_ping_gate.dart';

void main() {
  test('gate header is the one portnook expects', () {
    expect(
      PushPingGate.sign('0123456789abcdef', 'ab' * 32, 1795000000),
      'v1.0123456789abcdef.1795000000.d41d9f3b30bd2f1984450fde153647383c877c8c06d5d017bb89ef29b417193a',
    );
  });

  test('only the installed lookup decides, per origin', () {
    PushPingGate.install(
      (uri) => PushPingGate.originOf(uri) == 'https://tv.example.ch:41000'
          ? 'v1.x'
          : null,
    );
    expect(PushPingGate.headersFor('https://TV.example.ch:41000/Items'), {
      'X-PN-Gate': 'v1.x',
    });
    expect(PushPingGate.headersFor('https://tv.example.ch:41001/Items'), isEmpty);
    expect(PushPingGate.headersFor('https://image.tmdb.org/x.jpg'), isEmpty);
  });
}
