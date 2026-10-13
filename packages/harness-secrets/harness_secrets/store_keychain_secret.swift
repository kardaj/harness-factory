#!/usr/bin/env swift
import Darwin
import Foundation
import Security

func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data("[keychain-store][error] \(message)\n".utf8))
  exit(1)
}

// Fail rather than asking for a password or changing an item's access policy.
SecKeychainSetUserInteractionAllowed(false)

var arguments = Array(CommandLine.arguments.dropFirst())
var keychain: SecKeychain?
if arguments.first == "--keychain" {
  guard arguments.count >= 2,
    SecKeychainOpen(arguments[1], &keychain) == errSecSuccess
  else {
    fail("Unable to open the Keychain.")
  }
  arguments.removeFirst(2)
}
let modes = ["--read", "--put", "--delete", "--list", "--inspect", "--delete-if-unchanged"]
let mode = modes.contains(arguments.first ?? "") ? arguments[0] : "legacy"
let metadataMode = ["--list", "--inspect", "--delete-if-unchanged"].contains(mode)
let expectedCount = metadataMode ? 2 : (mode == "--put" ? 4 : 3)
guard arguments.count == expectedCount else {
  fail(
    "Usage: store_keychain_secret.swift [--keychain PATH] SERVICE ACCOUNT LABEL | --put SERVICE ACCOUNT LABEL | --read SERVICE ACCOUNT | --delete SERVICE ACCOUNT | --list SERVICE | --inspect SERVICE | --delete-if-unchanged SERVICE"
  )
}

let offset = mode == "legacy" ? 0 : 1
let service = arguments[offset]
var lookup: [CFString: Any] = [
  kSecClass: kSecClassGenericPassword,
  kSecAttrService: service,
]
if !metadataMode {
  lookup[kSecAttrAccount] = arguments[offset + 1]
}
if let keychain {
  lookup[kSecUseKeychain] = keychain
  lookup[kSecMatchSearchList] = [keychain]
}

func readItem() -> Data {
  var query = lookup
  query[kSecUseAuthenticationUI] = kSecUseAuthenticationUIFail
  query[kSecMatchLimit] = kSecMatchLimitOne
  query[kSecReturnData] = true
  var result: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &result)
  if status == errSecItemNotFound {
    exit(44)
  }
  guard status == errSecSuccess, let data = result as? Data else {
    fail("Unable to read the Keychain item.")
  }
  return data
}

if mode == "--read" {
  FileHandle.standardOutput.write(readItem())
  exit(0)
}

if mode == "--delete" {
  let status = SecItemDelete(lookup as CFDictionary)
  guard status == errSecSuccess || status == errSecItemNotFound else {
    fail("Unable to delete the Keychain item.")
  }
  exit(0)
}

let formatter = ISO8601DateFormatter()
formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

func metadata(_ item: [CFString: Any]) -> [String: Any] {
  guard let account = item[kSecAttrAccount] as? String,
    let created = item[kSecAttrCreationDate] as? Date,
    let modified = item[kSecAttrModificationDate] as? Date,
    let reference = item[kSecValuePersistentRef] as? Data, !reference.isEmpty,
    item[kSecAttrService] as? String == service
  else {
    fail("Unable to inspect Keychain metadata.")
  }
  var synchronizable = false
  if let value = item[kSecAttrSynchronizable] {
    guard CFGetTypeID(value as CFTypeRef) == CFBooleanGetTypeID(), let flag = value as? Bool else {
      fail("Unable to inspect Keychain metadata.")
    }
    synchronizable = flag
  }
  return [
    "account": account,
    "created_at": formatter.string(from: created),
    "modified_at": formatter.string(from: modified),
    "has_access_control": item[kSecAttrAccessControl] != nil,
    "synchronizable": synchronizable,
    "persistent_ref": reference.base64EncodedString(),
  ]
}

func emitMetadata(_ items: [[String: Any]]) -> Never {
  let payload: [String: Any] = ["schema_version": 2, "items": items]
  guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
  else {
    fail("Unable to inspect Keychain metadata.")
  }
  FileHandle.standardOutput.write(data)
  exit(0)
}

if mode == "--list" {
  var query = lookup
  query[kSecUseAuthenticationUI] = kSecUseAuthenticationUIFail
  query[kSecAttrSynchronizable] = kSecAttrSynchronizableAny
  query[kSecMatchLimit] = kSecMatchLimitAll
  query[kSecReturnAttributes] = true
  query[kSecReturnData] = false
  query[kSecReturnPersistentRef] = true
  var result: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &result)
  if status == errSecItemNotFound {
    exit(44)
  }
  guard status == errSecSuccess, let attributes = result as? [[CFString: Any]] else {
    fail("Unable to list Keychain items.")
  }
  let items = attributes.map(metadata).sorted {
    ($0["account"] as! String) < ($1["account"] as! String)
  }
  emitMetadata(items)
}

if mode == "--inspect" || mode == "--delete-if-unchanged" {
  guard
    let expected = try? JSONSerialization.jsonObject(
      with: FileHandle.standardInput.readDataToEndOfFile()) as? [String: Any],
    let version = expected["schema_version"] as? NSNumber,
    CFGetTypeID(version) != CFBooleanGetTypeID(), version == 2,
    !["d", "f"].contains(String(cString: version.objCType)),
    let encoded = expected["persistent_ref"] as? String,
    let reference = Data(base64Encoded: encoded), !reference.isEmpty
  else {
    fail("Invalid Keychain metadata request.")
  }
  let fields: Set<String> =
    mode == "--inspect"
    ? ["schema_version", "persistent_ref"]
    : [
      "schema_version", "account", "created_at", "modified_at", "has_access_control",
      "synchronizable", "persistent_ref",
    ]
  guard Set(expected.keys) == fields else { fail("Invalid Keychain metadata request.") }
  // Both operations target only this captured reference, never an account name.
  var referenceQuery = lookup
  referenceQuery[kSecValuePersistentRef] = reference
  referenceQuery[kSecUseAuthenticationUI] = kSecUseAuthenticationUIFail
  var query = referenceQuery
  query[kSecAttrSynchronizable] = kSecAttrSynchronizableAny
  query[kSecMatchLimit] = kSecMatchLimitOne
  query[kSecReturnAttributes] = true
  query[kSecReturnPersistentRef] = true
  query[kSecReturnData] = false
  var result: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &result)
  if status == errSecItemNotFound { exit(44) }
  guard status == errSecSuccess, let attributes = result as? [CFString: Any] else {
    fail("Unable to inspect Keychain metadata.")
  }
  if attributes[kSecAttrService] as? String != service { exit(44) }
  let current = metadata(attributes)
  if mode == "--inspect" { emitMetadata([current]) }
  for name in ["has_access_control", "synchronizable"] {
    guard let flag = expected[name] as? NSNumber, CFGetTypeID(flag) == CFBooleanGetTypeID() else {
      fail("Invalid Keychain metadata request.")
    }
    // Guarded sweeping always preserves protected and synchronized items.
    if flag.boolValue || current[name] as? Bool != false { exit(45) }
  }
  for name in ["created_at", "modified_at"] {
    guard let text = expected[name] as? String, let date = formatter.date(from: text),
      let currentText = current[name] as? String,
      let currentDate = formatter.date(from: currentText)
    else {
      fail("Invalid Keychain metadata request.")
    }
    if date != currentDate { exit(45) }
  }
  guard let account = expected["account"] as? String else {
    fail("Invalid Keychain metadata request.")
  }
  if account != current["account"] as? String || encoded != current["persistent_ref"] as? String {
    exit(45)
  }
  // There remains a race after this check. SecItemDelete has no compare-and-delete API.
  let deleted = SecItemDelete(referenceQuery as CFDictionary)
  if deleted == errSecItemNotFound { exit(44) }
  guard deleted == errSecSuccess else { fail("Unable to delete the Keychain item.") }
  exit(0)
}

let label = arguments[offset + 2]
var secret = FileHandle.standardInput.readDataToEndOfFile()
if mode == "legacy" {
  // Preserve the setup helper's original newline trimming. --put is exact.
  while secret.last == 10 || secret.last == 13 {
    secret.removeLast()
  }
  guard !secret.isEmpty else {
    fail("Refusing to store an empty secret.")
  }
}

// Update in place. macOS may regenerate the partition ACL for this identity.
let updatedAttributes: [CFString: Any] = [
  kSecAttrLabel: label,
  kSecValueData: secret,
]

var status = SecItemUpdate(lookup as CFDictionary, updatedAttributes as CFDictionary)
if status == errSecItemNotFound {
  var item = lookup
  item.merge(updatedAttributes) { _, replacement in replacement }
  status = SecItemAdd(item as CFDictionary, nil)
}
guard status == errSecSuccess else {
  fail("Unable to store the Keychain item.")
}

guard readItem() == secret else {
  fail("The Keychain item did not preserve the complete secret.")
}
