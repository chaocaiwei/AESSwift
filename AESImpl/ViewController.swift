//
//  ViewController.swift
//  AESImpl
//
//  Created by myself on 2020/4/9.
//  Copyright © 2020 myself. All rights reserved.
//

import UIKit
import CommonCrypto


class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
//        testAESiOS()
        testAESImpl()
//        testProgress()
//        testAddRoundKey()
        

//        let state : [UInt8]  = [0x66,0x03,0x10,0x40,0x71,0x51,0x8b,0x2c,0x4b,0x9c,0x89,0x97,0x1f,0xc6,0xe0,0xfb]
//        let key   : [UInt8]  = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16]
//        let crop  = AESImpl(key: key)!
//        let s0    = crop.decrypt(state)
//        print(s0)
        
        
        
    }
    
    func testProgress () {
        var state = Matrix(data: [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16])
        print("state\n",state)
        state = AESImpl.subBytes(state)
        print("subBytes\n",state)
        state = AESImpl.invSubBytes(state)
        print("invSubBytes\n",state)
        state = AESImpl.shiftRows(state)
        print("shiftRows\n",state)
        state = AESImpl.invShiftRows(state)
        print("invShiftRows\n",state)
        state = AESImpl.mixColumns(state)
        print("mixColumns\n",state)
        state = AESImpl.invMixColumns(state)
        print("invMixColumns\n",state)
    }
    
    func testAddRoundKey () {
        var state          = Matrix(data: [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16])
        let key : [UInt8]  = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16]
        let crop  = AESImpl(key: key)!
        print("state\n",state)
        for i in 0...10 {
            state = crop.addRoundKey(state, round: i)
            print("addRoundKey i=\(i)\n",state)
            state = crop.addRoundKey(state, round: i)
            print("re addRoundKey i=\(i)\n",state)
        }
    }
    
    
    func testAESImpl () {
        let state  : [UInt8]  = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16]
        let key    : [UInt8]  = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16]
        let crop   = AESImpl(key: key)!
        let mw     = crop.encrypt(state)
        let hy     = crop.decrypt([UInt8](mw))
        print(Matrix(data: state))
        print(Matrix(data: mw))
        print(Matrix(data: hy))
    }
    
    func testAESiOS () {
        let password = "UserPassword1!"
        let key128   = "1234567890123456".data(using:.utf8)!
        let key256   = "12345678901234561234567890123456".data(using:.utf8)!
        let iv       = "abcdefghijklmnop".data(using:.utf8)!


        let aes128 = AESCrypto(key: key128, iv: iv)
        let aes256 = AESCrypto(key: key256, iv: iv)
        let encryptedPassword128 = aes128?.encrypt(string: password)
        let descry128 = aes128?.decrypt(data: encryptedPassword128)
        let encryptedPassword256 = aes256?.encrypt(string: password)
        let decry256 = aes256?.decrypt(data: encryptedPassword256)
        debugPrint(descry128!)
        debugPrint(decry256!)
    }
    


}


class AESCrypto {
    
    private let key: Data
    private let iv: Data
    
    init?(key: Data, iv: Data) {
        guard key.count == kCCKeySizeAES128 || key.count == kCCKeySizeAES256 else {
            debugPrint("Error: Failed to set a key.")
            return nil
        }
        
        guard iv.count == kCCBlockSizeAES128 else {
            debugPrint("Error: Failed to set an initial vector.")
            return nil
        }

        self.key = key
        self.iv  = iv
    }
    
    func encrypt(string: String) -> Data? {
        return crypt(data: string.data(using: .utf8), option: CCOperation(kCCEncrypt))
    }

    func decrypt(data: Data?) -> String? {
        guard let decryptedData = crypt(data: data, option: CCOperation(kCCDecrypt)) else { return nil }
        return String(bytes: decryptedData, encoding: .utf8)
    }
    
    func crypt(data: Data?, option: CCOperation) -> Data? {
        guard let data = data else { return nil }

        let cryptLength = data.count + kCCBlockSizeAES128
        var cryptData   = Data(count: cryptLength)

        let keyLength = key.count
        let options   = CCOptions(kCCOptionPKCS7Padding)
        
        var bytesLength = Int(0)
        
        let status = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                iv.withUnsafeBytes { ivBytes in
                    key.withUnsafeBytes { keyBytes in
                    CCCrypt(option, CCAlgorithm(kCCAlgorithmAES), options, keyBytes.baseAddress, keyLength, ivBytes.baseAddress, dataBytes.baseAddress, data.count, cryptBytes.baseAddress, cryptLength, &bytesLength)
                    }
                }
            }
        }

        guard UInt32(status) == UInt32(kCCSuccess) else {
            debugPrint("Error: Failed to crypt data. Status \(status)")
            return nil
        }

        cryptData.removeSubrange(bytesLength..<cryptData.count)
        return cryptData
    }
    
    
    
    
}

