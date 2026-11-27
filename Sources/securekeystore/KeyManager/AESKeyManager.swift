import Security
import Foundation

class AESKeyManager: BaseKeyManagerImpl {
    override var keyType: KeyType {
        return .aes
    }

    override func generateKeyPair(tag: String, completion: @escaping (Bool, SecKey?, SecKey?) -> Void) {
        do {
            let keyPair = try SecureEnclaveKeyFactory(keyType: keyType, accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly).createKeyPair(tag: tag)
            completion(true, keyPair.privateKey, keyPair.publicKey)
        } catch {
            print("Error creating encryption key: \(error)")
            completion(false, nil, nil)
        }
    }
}
