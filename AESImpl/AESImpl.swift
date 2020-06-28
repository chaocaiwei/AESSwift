//
//  AESImpl.swift
//  AESImpl
//
//  Created by myself on 2020/4/9.
//  Copyright © 2020 myself. All rights reserved.
//

import UIKit



// The number of columns comprising a state in AES. This is a constant in AES. Value=4
//#define Nb 4
//
//#if defined(AES256) && (AES256 == 1)
//    #define Nk 8
//    #define Nr 14
//#elif defined(AES192) && (AES192 == 1)
//    #define Nk 6
//    #define Nr 12
//#else
//    #define Nk 4        // The number of 32 bit words in a key.
//    #define Nr 10       // The number of rounds in AES Cipher.
//#endif


// AES128
private let Nb  = 4   // The number of columns comprising a state in AES
private let Nk  = 4   // The number of 32 bit words in a key.
private let Nr  = 10  // 轮数 The number of rounds in AES Cipher.

class AESImpl {
    
    private  let key: [UInt8]
    var roundKeys = [Matrix]()
    
    init?(key: [UInt8]) {
        guard key.count == 16 || key.count == 32 else {
            debugPrint("Error: Failed to set a key.")
            return nil
        }
        self.key  = key
       
        self.roundKeys = AESImpl.keyExpansion(key)
   }
    
    static func keyExpansion(_ key: [UInt8]) -> [Matrix] {
        var roundKeys = [Matrix](repeating: Matrix.zero, count: Nr + 1)
        
        // The first round key is the key itself.
        roundKeys[0]  = Matrix(data: key)
        
        for round in 1...Nr {
            var words = roundKeys[round-1].words
            words[0] = words[3].g(round: round)  ^ words[0]
            words[1] = words[0] ^ words[1]
            words[2] = words[1] ^ words[2]
            words[3] = words[2] ^ words[3]
            roundKeys[round] = Matrix(words: words)
        }
        
        return roundKeys
    }
    
    func encrypt(_ data: [UInt8]) -> [UInt8] {
        var state = Matrix(data: data)
        state =  addRoundKey(state, round: 0)
        var i = 1
        while true {
            state =  AESImpl.subBytes(state)
            state =  AESImpl.shiftRows(state)
            if i == Nr {
                break
            }
            state =  AESImpl.mixColumns(state)
            state =  addRoundKey(state,round: i)
            i += 1
        }
        state =  addRoundKey(state, round: Nr)
        return state.data
    }
    
    func decrypt(_ data: [UInt8]) -> [UInt8] {
        var state = Matrix(data: data)
        state = addRoundKey(state, round: Nr)
       
        var i  = Nr - 1
        while true {
            state = AESImpl.invShiftRows(state)
            state = AESImpl.invSubBytes(state)
            state = addRoundKey(state, round: i)
            if i == 0 {
                break
            }
            state = AESImpl.invMixColumns(state)
            i -= 1
        }
        
        return state.data
    }
    
    func addRoundKey (_ state:Matrix,round: Int) -> Matrix {
        let roundKey = self.roundKeys[round]
        var content  = state.content
        for (i,subArr) in content.enumerated() {
           for (j,_) in subArr.enumerated() {
               content[i][j] ^= roundKey.content[i][i]
           }
       }
        return Matrix(content: content)
    }
    
    static func subBytes(_ state: Matrix) -> Matrix
    {
        var content  = [UInt8].init(repeating: 0, count: 16)
        for (i,subArr) in state.content.enumerated() {
          for (j,value) in subArr.enumerated() {
              let index = i * 4 + j
              content[index] =  kSbox[Int(value)]
          }
        }
        return Matrix(data: content)
    }
    
    static func invSubBytes(_ state: Matrix) -> Matrix
    {
        var content  = [UInt8](repeating: 0, count: 16)
        for (i,subArr) in state.content.enumerated() {
          for (j,value) in subArr.enumerated() {
              let index = i * 4 + j
              content[index] =  kInvSBox[Int(value)]
          }
        }
        return Matrix(data: content)
    }
    
    static func shiftRows (_ state: Matrix) -> Matrix {
        
       var state = state
       var temp : UInt8 = 0

       // Rotate first row 1 columns to left
       temp         = state[0][1]
       state[0][1]  = state[1][1]
       state[1][1]  = state[2][1]
       state[2][1]  = state[3][1]
       state[3][1]  = temp

       // Rotate second row 2 columns to left
       let temp0    = state[0][2]
       let temp1    = state[1][2]
       state[0][2]  = state[2][2]
       state[1][2]  = state[3][2]
       state[2][2]  = temp0
       state[3][2]  = temp1

       // Rotate third row 3 columns to left
       temp         = state[0][3]
       state[0][3]  = state[3][3]
       state[3][3]  = state[2][3]
       state[2][3]  = state[1][3]
       state[1][3]  = temp
        
        return state
    }
    
    static func invShiftRows (_ state: Matrix) -> Matrix {
        var state = state
        var temp : UInt8 = 0

        // Rotate first row 1 columns to right
        temp         = state[0][1]
        state[0][1]  = state[3][1]
        state[3][1]  = state[2][1]
        state[2][1]  = state[1][1]
        state[1][1]  = temp

        // Rotate second row 2 columns to right
        let temp0    = state[0][2]
        let temp1    = state[1][2]
        state[0][2]  = state[2][2]
        state[1][2]  = state[3][2]
        state[2][2]  = temp0
        state[3][2]  = temp1

        // Rotate third row 3 columns to right
        temp         = state[0][3]
        state[0][3]  = state[1][3]
        state[1][3]  = state[2][3]
        state[2][3]  = state[3][3]
        state[3][3]  = temp
        
        return state
    }
    
    static func mixColumns (_ state: Matrix) -> Matrix {
        
        var state = state
        var t    : UInt8 = 0
        var Temp : UInt8 = 0
        var Tm   : UInt8 = 0
        
        for i in 0..<4 {
            t            = state[i][0]
            Temp         = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3]
            
            Tm           = state[i][0] ^ state[i][1]
            Tm           = xtime(Tm)
            state[i][0]  ^= Tm ^ Temp
            
            Tm           = state[i][1] ^ state[i][2]
            Tm           = xtime(Tm)
            state[i][1]  ^= Tm ^ Temp
            
            Tm           = state[i][2] ^ state[i][3]
            Tm           = xtime(Tm)
            state[i][2]  ^= Tm ^ Temp
            
            Tm           = state[i][3] ^ t
            Tm           = xtime(Tm)
            state[i][3]  ^= Tm ^ Temp
        }
        
        return state
    }
    
    static func invMixColumns (_ state: Matrix) -> Matrix {
        var state = state
        for i in 0..<4 {
            let a = state[i][0]
            let b = state[i][1]
            let c = state[i][2]
            let d = state[i][3]
            
            state[i][0]  = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09)
            state[i][1]  = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d)
            state[i][2]  = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b)
            state[i][3]  = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e)
        }
        
        return state
    }
    
    static func multiply (_ x: UInt8,_ y: UInt8) -> UInt8 {
        var result =   (y & 1) * x
            result ^=  (y>>1 & 1) * xtime(x)
            result ^=  (y>>2 & 1) * xtime(xtime(x))
            result ^=  (y>>3 & 1) * xtime(xtime(xtime(x)))
            result ^=  (y>>4 & 1) * xtime(xtime(xtime(xtime(x))))
       return result
    }
    
    
    static func xtime (_ x: UInt8) -> UInt8 {
        return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
    }
    
    
    private func slice(data: Data) -> [[UInt8]] {
        let size = 16
        var result = [[UInt8]]()
        for (index,item) in data.enumerated() {
            if index % size == 0 {
                result.append([item])
            } else {
                result[index/size].append(item)
            }
        }
        return result
    }
    
   
}






extension Array where Element == UInt8 {
  func to32BitArray () -> [UInt32] {
      var i = 0
      var result = [UInt32]()
      while i < self.count {
        let count = self.count - i < 4 ?  self.count - i - 1 : 3
        var res : UInt32 = 0
        for j in 0...count {
            let index = i + j
            let dis = 8 * (count - j)
            res += UInt32(self[index]) << dis
        }
        i += 4
        result.append(res)
      }
     return result
  }
}




/* aes sbox  */
let kSbox : [UInt8] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

/* aes  invert-sbox */
let kInvSBox : [UInt8]  = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

let kMixArr : [UInt8] = [
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02
]
