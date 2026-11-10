import 'package:flutter/material.dart';

import '../errors.dart';
import '../push.dart';
import 'strings.dart';

/// State behind [PushApprovalsView], the twin of the native `PushApprovalsModel`: the pending
/// approvals (expired ones dropped, the focused one first), approve / deny, and a wrong number keeping
/// its card for another try.
class PushApprovalsController extends ChangeNotifier {
  PushApprovalsController({required this.push, this.focus, this.onResponded, DateTime Function()? clock}) : _clock = clock ?? DateTime.now;

  final Push push;

  /// The `cid` a notification pointed at (shown first).
  final String? focus;
  final void Function(PendingApproval approval, String status)? onResponded;
  final DateTime Function() _clock;

  List<PendingApproval> approvals = const [];
  bool isLoading = false;
  bool isBusy = false;
  String? message;
  bool _disposed = false;

  Future<void> refresh() async {
    isLoading = true;
    _notify();
    try {
      final list = (await push.pendingApprovals()).where((a) => !a.isExpired(_clock())).toList()
        ..sort((a, b) => (a.cid == focus ? 0 : 1).compareTo(b.cid == focus ? 0 : 1));
      approvals = list;
      message = null;
    } on NativeAuthException catch (e) {
      message = e.description ?? e.code;
    } finally {
      isLoading = false;
      _notify();
    }
  }

  Future<void> respond(PendingApproval approval, PushApprovalAction action) async {
    isBusy = true;
    _notify();
    try {
      final status = await push.respond(approval, action);
      approvals = approvals.where((a) => a.cid != approval.cid).toList();
      message = null;
      onResponded?.call(approval, status);
    } on NativeAuthException catch (e) {
      message = e.description ?? e.code;
      // A wrong number keeps the card (one more try, spec/05 §5); anything else refreshes.
      if (e.code != NativeAuthErrorCode.userVerificationMismatch) await refresh();
    } finally {
      isBusy = false;
      _notify();
    }
  }

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }
}

/// The pending sign-in approvals of this device's user (spec/05 §5): one card per approval with
/// Approve / Deny, the three number-match buttons when the request has them or a PIN field, and a
/// refresh button. Show it from a notification tap and when the app opens; a backgrounded app does
/// not see push data until the user taps. Twin of the native `PushApprovalsView` / `PushApprovalsScreen`.
class PushApprovalsView extends StatefulWidget {
  const PushApprovalsView({super.key, required this.push, this.focus, this.onResponded, this.strings, @visibleForTesting this.clock});

  /// `kc.push`.
  final Push push;
  final String? focus;
  final void Function(PendingApproval approval, String status)? onResponded;
  final NativeLoginStrings? strings;

  /// The time expired approvals are dropped against (tests).
  final DateTime Function()? clock;

  @override
  State<PushApprovalsView> createState() => _PushApprovalsViewState();
}

class _PushApprovalsViewState extends State<PushApprovalsView> {
  late final PushApprovalsController _controller = PushApprovalsController(push: widget.push, focus: widget.focus, onResponded: widget.onResponded, clock: widget.clock)
    ..addListener(_changed)
    ..refresh();

  void _changed() => setState(() {});

  @override
  void dispose() {
    _controller.removeListener(_changed);
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final s = widget.strings ?? NativeLoginStrings.of(context);
    final theme = Theme.of(context);
    final c = _controller;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(s.pushRequests, style: theme.textTheme.titleLarge),
            TextButton(key: const ValueKey('pushRefresh'), onPressed: c.isLoading ? null : c.refresh, child: Text(s.refresh)),
          ],
        ),
        if (c.approvals.isEmpty)
          Text(c.isLoading ? s.contactingServer : s.pushNoRequests, key: const ValueKey('pushNoApprovals'), style: TextStyle(color: theme.colorScheme.onSurfaceVariant)),
        for (final approval in c.approvals) _ApprovalCard(approval: approval, busy: c.isBusy, strings: s, respond: (action) => c.respond(approval, action)),
        if (c.message case final message?)
          Text(message, key: const ValueKey('pushApprovalsMessage'), style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error)),
      ],
    );
  }
}

class _ApprovalCard extends StatefulWidget {
  const _ApprovalCard({required this.approval, required this.busy, required this.strings, required this.respond});

  final PendingApproval approval;
  final bool busy;
  final NativeLoginStrings strings;
  final void Function(PushApprovalAction action) respond;

  @override
  State<_ApprovalCard> createState() => _ApprovalCardState();
}

class _ApprovalCardState extends State<_ApprovalCard> {
  final _pin = TextEditingController();

  @override
  void dispose() {
    _pin.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final a = widget.approval;
    final s = widget.strings;
    final theme = Theme.of(context);
    final muted = theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant);
    final expires = a.expiresAt?.toLocal();
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          spacing: 8,
          children: [
            Text(s.pushSignInTo(a.clientDisplayName), style: theme.textTheme.titleMedium),
            if (a.username case final username?) Text(username, style: muted),
            if (a.numbers.isNotEmpty) ...[
              Text(s.pushPickNumber, style: muted),
              Row(
                spacing: 12,
                children: [
                  for (final number in a.numbers)
                    FilledButton(
                      key: ValueKey('pushNumber-$number'),
                      onPressed: widget.busy ? null : () => widget.respond(PushApprovalAction.approve(number)),
                      child: Text(number, style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
                    ),
                ],
              ),
            ] else if (a.requiresPin) ...[
              TextField(key: const ValueKey('pushPin'), controller: _pin, keyboardType: TextInputType.number, decoration: InputDecoration(labelText: s.pushPin, border: const OutlineInputBorder())),
              FilledButton(
                key: const ValueKey('pushApprove'),
                onPressed: widget.busy ? null : () => widget.respond(PushApprovalAction.approve(_pin.text)),
                child: Text(s.approve),
              ),
            ] else
              FilledButton(key: const ValueKey('pushApprove'), onPressed: widget.busy ? null : () => widget.respond(const PushApprovalAction.approve()), child: Text(s.approve)),
            OutlinedButton(
              key: const ValueKey('pushDeny'),
              onPressed: widget.busy ? null : () => widget.respond(const PushApprovalAction.deny()),
              child: Text(s.deny, style: TextStyle(color: theme.colorScheme.error)),
            ),
            if (expires != null)
              Text(s.pushExpires('${expires.hour.toString().padLeft(2, '0')}:${expires.minute.toString().padLeft(2, '0')}'), style: muted),
          ],
        ),
      ),
    );
  }
}
