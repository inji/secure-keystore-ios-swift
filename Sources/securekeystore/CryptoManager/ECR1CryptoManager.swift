import Security
import Foundation

class ECR1CryptoManager: BaseCryptoManagerImpl {

    /// ECDSA P-256 with SHA-256, run inside the Secure Enclave; returns the DER-encoded signature.
    func sign(data: Data, withKeyTag keyTag: String, completion: @escaping (Result<Data, KeystoreFailure>) -> Void) {
        fetchPrivateKeyRef(tag: keyTag) { success, privateKey, resultMessage in
            guard success, let privateKey else {
                completion(.failure(KeystoreFailure(.keyNotFound, resultMessage ?? "Key not found")))
                return
            }
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) as Data? else {
                completion(.failure(KeystoreFailure(.signingFailed, error: error, fallback: "EC signing failed")))
                return
            }
            completion(.success(signature))
        }
    }
}
