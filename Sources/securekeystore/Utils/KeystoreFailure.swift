import Foundation

enum KeystoreErrorCode: String {
    case keyNotFound = "KEY_NOT_FOUND"
    case keyGenerationError = "KEY_GENERATION_ERROR"
    case unsupportedKeyType = "UNSUPPORTED_KEY_TYPE"
    case unsupportedAlgorithm = "UNSUPPORTED_ALGORITHM"
    case secureEnclaveUnavailable = "SECURE_ENCLAVE_UNAVAILABLE"
    case invalidInput = "INVALID_INPUT"
    case signingFailed = "SIGNING_FAILED"
    case encryptionFailed = "ENCRYPTION_FAILED"
    case decryptionFailed = "DECRYPTION_FAILED"
}

struct KeystoreFailure: Error {
    let code: KeystoreErrorCode
    let message: String

    init(_ code: KeystoreErrorCode, _ message: String) {
        self.code = code
        self.message = message
    }

    init(_ code: KeystoreErrorCode, error: Unmanaged<CFError>?, fallback: String) {
        let description = error.map { ($0.takeRetainedValue() as Error).localizedDescription }
        self.init(code, description ?? fallback)
    }
}
