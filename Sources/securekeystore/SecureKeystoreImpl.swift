import Foundation
import Security

@available(iOS 13.0, *)
public class SecureKeystoreImpl:SecureKeystoreProtocol {
    
    private let keychainManager: KeychainManagerProtocol
    private let rsaCryptoManager: RSACryptoManager
    private let ecr1CryptoManager: ECR1CryptoManager
    private let aesCryptoManager: AESCryptoManager
    private let aesKeyManager: AESKeyManager
    private let biometrics: BiometricsProtocol
    private let iCloudStore = NSUbiquitousKeyValueStore.default
    
    public init() {
        self.biometrics=BiometricsImpl()
        self.keychainManager = KeychainManagerImpl(biometrics: biometrics)
        self.rsaCryptoManager = RSACryptoManager(keychainManager: keychainManager)
        self.ecr1CryptoManager = ECR1CryptoManager(keychainManager: keychainManager)
        self.aesKeyManager=AESKeyManager()
        self.aesCryptoManager=AESCryptoManager(keychainManager: keychainManager)
    }
    
    internal init(keychainManager: KeychainManagerProtocol,
                  rsaCryptoManager: RSACryptoManager,
                  ecr1CryptoManager: ECR1CryptoManager) {
        self.keychainManager = keychainManager
        self.rsaCryptoManager = rsaCryptoManager
        self.ecr1CryptoManager = ecr1CryptoManager
        self.biometrics=BiometricsImpl()
        self.aesKeyManager=AESKeyManager()
        self.aesCryptoManager=AESCryptoManager(keychainManager: keychainManager)
    }
    
    public func generateKeyPair(type: String, tag: String, isAuthRequired:Bool, authTimeout:Int32, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) {
        if type == "RSA" {
            let rsaKeyManager = RSAKeyManager()
            rsaKeyManager.generateKeyPair(tag: tag) { success, privateKey, publicKey in
                if success {
                    self.keychainManager.storeKey(key: privateKey!, tag: tag) { success in
                        setAuthTimeOutForKey(keyType: type, authTimeout:isAuthRequired == true ? TimeInterval(authTimeout):TimeInterval(Int.max))
                        onSuccess((publicKey!.toPKCS8PublicKeyString())!)
                    }
                } else {
                    onFailure("","Key storing error")
                }
            }
        } else if isES256(type) {
            let ecr1KeyManager = ECR1KeyManager()
            ecr1KeyManager.generateKeyPair(tag: tag) { success, _, publicKey in
                guard success, let publicKeyPem = publicKey?.toPKCS8PublicKeyString() else {
                    onFailure(KeystoreErrorCode.keyGenerationError.rawValue, "Unable to create the ES256 key in the Secure Enclave")
                    return
                }
                setAuthTimeOutForKey(keyType: tag, authTimeout: authTimeoutInterval(required: isAuthRequired, seconds: authTimeout))
                onSuccess(publicKeyPem)
            }
        } else {
            onFailure("","Key generation error")
        }
    }
    
    public func deleteKeyPair(tag: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) {
        keychainManager.deleteKey(tag: tag) { resultMessage in
            if resultMessage == "Key deleted successfully" {
                onSuccess(true)
            } else {
                onFailure("", resultMessage)
            }
        }
    }
    
    public func hasAlias(tag: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) {
        keychainManager.keyExists(tag: tag) { exists in
            exists == true ? onSuccess(exists) : onFailure("","Key does not exists")
        }
    }
    
    @available(iOS 13.0, *)
    public func sign(signAlgorithm: String, alias: String, data: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) {
        guard let messageData = data.data(using: .ascii) else {
            onFailure("","Message conversion failed")
            return
        }
        
        if signAlgorithm == "RSA" {
            rsaCryptoManager.sign(data: messageData, withKeyTag: alias){
                sign in
                (sign != nil) ? onSuccess(sign!) : onFailure("","RSA signing failed")
            }
        } else if isES256(signAlgorithm) {
            ecr1CryptoManager.sign(data: messageData, withKeyTag: alias) { result in
                deliver(result.map { $0.base64URLEncodedString() }, onSuccess: onSuccess, onFailure: onFailure)
            }
        } else {
            onFailure("","Invalid key type")
        }
        
    }
    
    /// Signs raw bytes with the ES256 key; takes and returns base64, the signature DER-encoded as on Android.
    public func signBytes(signAlgorithm: String, alias: String, dataBase64: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) {
        guard isES256(signAlgorithm) else {
            onFailure(KeystoreErrorCode.unsupportedAlgorithm.rawValue, "signBytes supports ES256 only")
            return
        }
        guard let data = Data(base64Encoded: dataBase64) else {
            onFailure(KeystoreErrorCode.invalidInput.rawValue, "Data to sign is not base64")
            return
        }
        ecr1CryptoManager.sign(data: data, withKeyTag: alias) { result in
            deliver(result.map { $0.base64EncodedString() }, onSuccess: onSuccess, onFailure: onFailure)
        }
    }

    public func retrieveKey(tag: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void){
        keychainManager.retrievePublicKey(tag: tag) { publicKey in
            guard let publicKeyPem = publicKey?.toPKCS8PublicKeyString() else {
                onFailure(KeystoreErrorCode.keyNotFound.rawValue, "No public key found for \(tag)")
                return
            }
            onSuccess(publicKeyPem)
        }
    }
    
    public func storeGenericKey(publicKey: String, privateKey: String, account: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping (_ code: String, _ message: String) -> Void) {
        let keyPair = ["privateKey": privateKey, "publicKey": publicKey]
        let signingKeysWithTimeOut: [String] = ["ES256K", "ED25519", "RS256", "ES256"]
        
        do {
            let serializedKeyPair = try NSKeyedArchiver.archivedData(withRootObject: keyPair, requiringSecureCoding: false)
            keychainManager.storeGenericKey(data: serializedKeyPair, account: account) { success in
                let timeout: TimeInterval = signingKeysWithTimeOut.contains(account) ? TimeInterval(0) : TimeInterval(-1)
                setAuthTimeOutForKey(keyType: account, authTimeout: timeout)
                success ? onSuccess(true) : onFailure("STORE_ERROR", "Key storing failed")
            }
        } catch {
            onFailure("SERIALIZATION_ERROR", "Failed to serialize key pair")
        }
    }
    
    public func retrieveGenericKey(account: String, onSuccess: @escaping (String?,String?) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) {
        keychainManager.retrieveGenericKey(account: account) { data, resultMessage in
            if let data = data {
                do {
                    if let keyPair = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data) as? [String: String?],
                       let privateKey = keyPair["privateKey"],
                       let publicKey = keyPair["publicKey"]{
                        onSuccess(privateKey, publicKey)
                    } else {
                        onFailure("DESERIALIZATION_ERROR", "Failed to deserialize key pair")
                    }
                } catch {
                    onFailure("DESERIALIZATION_ERROR", "Failed to deserialize key pair")
                }
            } else {
                let errorMessage = (resultMessage?.isEmpty == true) ? "Key retrieving error" : resultMessage!
                onFailure("", errorMessage)
            }
        }
    }
    
    public func hasBiometricsEnabled()->Bool{
        return biometrics.hasBiometricsEnabled()
    }
    
    public func getAvailableBiometricType()->String{
        return biometrics.getAvailableBiometricType()
    }
    
    public func updatePopup(title:String, desc:String){
        BiometricsImpl.updatePopup(title: title, desc:desc)
    }
    
    public func generateKey(alias: String, authRequired:Bool, authTimeout:Int32, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void){
        keychainManager.keyExists(tag: alias) { exists in
            if exists {
                onSuccess(true)
                return
            }
            self.aesKeyManager.generateKeyPair(tag: alias) { success, _, _ in
                guard success else {
                    onFailure(KeystoreErrorCode.keyGenerationError.rawValue, "Unable to create the encryption key in the Secure Enclave")
                    return
                }
                setAuthTimeOutForKey(keyType: alias, authTimeout: authTimeoutInterval(required: authRequired, seconds: authTimeout))
                onSuccess(true)
            }
        }
    }

    public func encryptData(alias:String, data:String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void)
    {
        aesCryptoManager.encrypt(keyTag: alias, data: data) { result in
            deliver(result, onSuccess: onSuccess, onFailure: onFailure)
        }
    }

    public func decryptData(alias:String, data:String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void)
    {
        aesCryptoManager.decrypt(keyTag: alias, data: data) { result in
            deliver(result, onSuccess: onSuccess, onFailure: onFailure)
        }
    }

    @available(iOS 13.0, *)
    public func generateHmacshaKey(alias:String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void){
        let hmacKeyManager: ()=HMACKeyManager().generateHmacshaKey(tag: alias){ success, key in
            if(!success){
                onFailure("", "HMAC key generation failed")
            }
            else{
                let data=key?.withUnsafeBytes { Data($0) }
                setAuthTimeOutForKey(keyType: alias, authTimeout:TimeInterval(-1))
                self.keychainManager.storeGenericKey(data:data , account: alias){
                    success in
                    if(success){
                        onSuccess(true)
                    }
                    else {
                        onFailure("","Key storing error")
                    }
                    
                }
            }
        }
    }
    
    @available(iOS 13.0, *)
    public func generateHmacSha(alias: String, data: String, onSuccess: @escaping (String?) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void){
        let hmac: ()=HMACCryptoManager(keychainManager: keychainManager).generateHmacSha(tag: alias, message: data){
            hash in
            if(hash != nil){
                onSuccess(hash)
            }
            else{
                onFailure("", "hash generation failed")
            }
        }
    }
    
    public func clearKeys(onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) -> Void {
        keychainManager.clearKeys(){
            success in if(success){
                onSuccess(success)
            }
            else{
                onFailure("", "key deletion failed")
            }
        }
    }
    
    /// iCloud CRUD operations
    public func storeValueInCloud(key: String, value: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping (String, String) -> Void) {
            iCloudStore.set(value, forKey: key)
            if iCloudStore.synchronize() {
                onSuccess(true)
            } else {
                onFailure("SYNC_FAILED", "Failed to synchronize iCloud Key-Value store.")
            }
        }
        
        
        public func retrieveValueFromCloud(key: String, onSuccess: @escaping (String?) -> Void, onFailure: @escaping (String, String) -> Void) {
            let value = iCloudStore.string(forKey: key)
            if let value = value {
                onSuccess(value)
            } else {
                onFailure("NOT_FOUND", "Key not found in iCloud Key-Value store.")
            }
        }
        
        
        public func removeValueFromCloud(key: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping (String, String) -> Void) {
            iCloudStore.removeObject(forKey: key)
            if iCloudStore.synchronize() {
                onSuccess(true)
            } else {
                onFailure("SYNC_FAILED", "Failed to synchronize iCloud Key-Value store.")
            }
        }
}

private func isES256(_ algorithm: String) -> Bool {
    algorithm == "ES256" || algorithm == "ECR1"
}

// -1 means the key never asks for user authentication
private func authTimeoutInterval(required: Bool, seconds: Int32) -> TimeInterval {
    required ? TimeInterval(seconds) : -1
}

private func deliver<T>(_ result: Result<T, KeystoreFailure>, onSuccess: (T) -> Void, onFailure: (_ code: String, _ message: String) -> Void) {
    switch result {
    case .success(let value): onSuccess(value)
    case .failure(let failure): onFailure(failure.code.rawValue, failure.message)
    }
}
