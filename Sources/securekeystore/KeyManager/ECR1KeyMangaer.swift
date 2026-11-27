import Security
import Foundation

class ECR1KeyManager: BaseKeyManagerImpl {
    override var keyType: KeyType {
        return .ecr1
    }

    override func generateKeyPair(tag: String, completion: @escaping (Bool, SecKey?, SecKey?) -> Void) {
        do {
            let keyPair = try SecureEnclaveKeyFactory(keyType: keyType, accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly).createKeyPair(tag: tag)
            completion(true, keyPair.privateKey, keyPair.publicKey)
        } catch {
            print("Error creating ECR1 key: \(error)")
            completion(false, nil, nil)
        }
    }
}
