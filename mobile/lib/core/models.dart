// Thin read-only views over the JSON the core returns.

class VaultRecord {
  VaultRecord(this.raw);
  final Map<String, dynamic> raw;

  String get id => raw['id'] as String;
  String get kind => (raw['kind'] as String?) ?? 'login';
  String get title => (raw['title'] as String?) ?? '';
  String get username => (raw['username'] as String?) ?? '';
  String get password => (raw['password'] as String?) ?? '';
  String get url => (raw['url'] as String?) ?? '';
  String get notes => (raw['notes'] as String?) ?? '';
  String? get totpSecret => raw['totp_secret'] as String?;
  Map<String, String> get fields =>
      ((raw['fields'] as Map?) ?? {}).map((k, v) => MapEntry(k as String, v as String));
  List<Map<String, dynamic>> get customFields =>
      ((raw['custom_fields'] as List?) ?? []).cast<Map<String, dynamic>>();
  String? get category => raw['category'] as String?;
  bool get categoryByUser => raw['category_source'] == 'user';
  String? get folder => raw['folder'] as String?;
  List<String> get tags => ((raw['tags'] as List?) ?? []).cast<String>();
  bool get favorite => (raw['favorite'] as bool?) ?? false;
  DateTime get updatedAt => DateTime.parse(raw['updated_at'] as String);

  /// What a list row shows under the title.
  String get subtitle {
    switch (kind) {
      case 'card':
        final n = fields['number'] ?? '';
        final last4 = n.replaceAll(RegExp(r'\D'), '');
        return last4.length >= 4 ? '•••• ${last4.substring(last4.length - 4)}' : (fields['brand'] ?? 'Card');
      case 'bank_account':
        return [fields['bank_name'], fields['account_number']].whereType<String>().join(' · ');
      case 'wifi':
        return fields['ssid'] ?? 'Wi-Fi';
      case 'server':
      case 'database':
        return fields['hostname'] ?? '';
      default:
        return username.isNotEmpty ? username : url;
    }
  }

  /// Editable copy in the shape the core's `add`/`update` accept.
  Map<String, dynamic> toInput() => {
        'kind': kind,
        'title': title,
        'username': username,
        'password': password,
        'url': url,
        'notes': notes,
        'totp_secret': totpSecret,
        'fields': Map<String, String>.from(fields),
        'custom_fields': customFields,
        'category': categoryByUser ? category : null,
        'folder': folder,
        'tags': tags,
        'favorite': favorite,
      };
}

class CategoryInfo {
  CategoryInfo(this.slug, this.label, this.count);
  final String slug;
  final String label;
  final int count;
}

const kindLabels = <String, String>{
  'login': 'Login',
  'bank_account': 'Bank account',
  'card': 'Payment card',
  'identity': 'Identity',
  'secure_note': 'Secure note',
  'wifi': 'Wi-Fi',
  'ssh_key': 'SSH key',
  'api_key': 'API key',
  'server': 'Server',
  'database': 'Database',
  'software_license': 'Software licence',
  'passkey': 'Passkey',
};

/// Human labels for type-specific field names.
String fieldLabel(String name) {
  const special = {
    'android_apps': 'Used in Android apps',
    'swift_bic': 'SWIFT / BIC',
    'iban': 'IBAN',
    'cvv': 'CVV',
    'pin': 'PIN',
    'kra_pin': 'KRA PIN',
    'id_number': 'ID number',
    'ssid': 'Network name (SSID)',
    'rp_id': 'Website',
  };
  if (special.containsKey(name)) return special[name]!;
  final words = name.split('_');
  return [words.first[0].toUpperCase() + words.first.substring(1), ...words.skip(1)].join(' ');
}

/// Fields that hold secrets and are masked until revealed.
const secretFields = {'cvv', 'pin', 'private_key', 'passphrase', 'secret', 'key', 'license_key', 'connection_string', 'number'};

/// Fields better edited as multi-line text.
const multilineFields = {'private_key', 'public_key', 'address', 'connection_string'};
