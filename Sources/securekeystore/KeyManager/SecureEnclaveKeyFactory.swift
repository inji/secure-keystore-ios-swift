import Foundation
import Security

// TODO: temporary security hardening; replace with the planned keystore architecture revamp
struct SecureEnclaveKeyFactory {
    let keyType: KeyType
    let accessibility: CFString

    func createKeyPair(tag: String) throws -> (privateKey: SecKey, publicKey: SecKey) {
        guard let secAttrKeyType = keyType.secAttrKeyType, secAttrKeyType == kSecAttrKeyTypeECSECPrimeRandom, keyType.keySize == 256 else {
            throw KeystoreFailure(.unsupportedKeyType, "The Secure Enclave supports P-256 EC keys only")
        }

        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, accessibility, .privateKeyUsage, &error) else {
            throw KeystoreFailure(.keyGenerationError, error: error, fallback: "Unable to create the key access control")
        }
        let privateKeyAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrLabel as String: tag + "label",
            kSecAttrAccessControl as String: access
        ]
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: secAttrKeyType,
            kSecAttrKeySizeInBits as String: keyType.keySize,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyAttributes
        ]

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw KeystoreFailure(.secureEnclaveUnavailable, error: error, fallback: "Unable to create a Secure Enclave key")
        }
        guard let applicationLabel = (SecKeyCopyAttributes(privateKey) as? [String: Any])?[kSecAttrApplicationLabel as String] as? Data,
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            deleteKey(privateKey)
            throw KeystoreFailure(.keyGenerationError, "Unable to read the new key")
        }
        // the old key is removed only once its replacement exists, so a failed generation never loses it
        do {
            try deleteKeys(tag: tag, except: applicationLabel)
        } catch {
            deleteKey(privateKey)
            throw error
        }
        return (privateKey, publicKey)
    }

    private func deleteKeys(tag: String, except keptApplicationLabel: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeystoreFailure(.keyGenerationError, "Unable to look up the keys to replace (\(status))")
        }
        let staleApplicationLabels = Set(((items as? [[String: Any]]) ?? [])
            .compactMap { $0[kSecAttrApplicationLabel as String] as? Data }
            .filter { $0 != keptApplicationLabel })
        for staleApplicationLabel in staleApplicationLabels {
            let deleteStatus = deleteKey(tag: tag, applicationLabel: staleApplicationLabel)
            guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
                throw KeystoreFailure(.keyGenerationError, "Unable to remove the key being replaced (\(deleteStatus))")
            }
        }
    }

    private func deleteKey(_ key: SecKey) {
        SecItemDelete([kSecValueRef as String: key] as CFDictionary)
    }

    private func deleteKey(tag: String, applicationLabel: Data) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrApplicationLabel as String: applicationLabel
        ]
        return SecItemDelete(query as CFDictionary)
    }
}
