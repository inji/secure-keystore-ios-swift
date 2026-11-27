import Foundation

class AESCryptoManager: BaseCryptoManagerImpl {

    private static let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    func encrypt(keyTag: String, data: String, completion: @escaping (Result<String, KeystoreFailure>) -> Void) {
        fetchPrivateKeyRef(tag: keyTag) { success, privateKey, resultMessage in
            guard success, let privateKey else {
                completion(.failure(KeystoreFailure(.keyNotFound, resultMessage ?? "Key not found")))
                return
            }
            guard let publicKey = SecKeyCopyPublicKey(privateKey), let plaintext = data.data(using: .utf8) else {
                completion(.failure(KeystoreFailure(.invalidInput, "Unable to prepare data for encryption")))
                return
            }
            var error: Unmanaged<CFError>?
            guard let encryptedData = SecKeyCreateEncryptedData(
                publicKey,
                Self.algorithm,
                plaintext as CFData,
                &error
            ) as Data? else {
                completion(.failure(KeystoreFailure(.encryptionFailed, error: error, fallback: "Encryption failed")))
                return
            }
            completion(.success(encryptedData.base64EncodedString()))
        }
    }

    func decrypt(keyTag: String, data: String, completion: @escaping (Result<String, KeystoreFailure>) -> Void) {
        fetchPrivateKeyRef(tag: keyTag) { success, privateKey, resultMessage in
            guard success, let privateKey else {
                completion(.failure(KeystoreFailure(.keyNotFound, resultMessage ?? "Key not found")))
                return
            }
            guard let cipherData = Data(base64Encoded: data) else {
                completion(.failure(KeystoreFailure(.invalidInput, "Encrypted data is not base64")))
                return
            }
            var error: Unmanaged<CFError>?
            guard let decryptedData = SecKeyCreateDecryptedData(
                privateKey,
                Self.algorithm,
                cipherData as CFData,
                &error
            ) as Data? else {
                completion(.failure(KeystoreFailure(.decryptionFailed, error: error, fallback: "Decryption failed")))
                return
            }
            guard let plaintext = String(data: decryptedData, encoding: .utf8) else {
                completion(.failure(KeystoreFailure(.decryptionFailed, "Decrypted data is not UTF-8")))
                return
            }
            completion(.success(plaintext))
        }
    }
}
