//
//  Word.swift
//  AESImpl
//
//  Created by myself on 2020/4/13.
//  Copyright © 2020 myself. All rights reserved.
//

import UIKit

func ^ (rh: AESImpl.Word,lh: AESImpl.Word) -> AESImpl.Word {
    return rh.xor(lh)
}

// 轮系数
private let kRcon : [UInt8] = [ 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 ]

extension AESImpl {
    
    // 32位bit的
    struct Word  {
        
        let content: [UInt8]
        
        init(_ content:[UInt8]) {
            self.content = content
        }
        
        init(value: UInt32) {
            let r0  = UInt8((value & 0xff000000) >> (3 * 8))
            let r1  = UInt8((value & 0xff0000)   >> (2 * 8))
            let r2  = UInt8((value & 0xff00)     >> (1 * 8))
            let r3  = UInt8(value & 0xff)
            self.init([r0,r1,r2,r3])
        }
        
        static func array(in data:[UInt8]) -> [Word] {
            var all = [[UInt8]]()
            for (index,sub) in data.enumerated() {
                if index % 4 == 0 {
                    all.append([sub])
                } else {
                    all[all.count-1].append(sub)
                }
            }
            let words = all.map({Word($0)})
            return words
        }
        
        
        var value : UInt32 {
            var res : UInt32 = 0
            for i in 0..<4 {
                res += UInt32(self.content[i]) << ((4 - i - 1) * 8)
            }
            return res
        }
    
        func g (round : Int) -> Word {
            var buf = [content[1], content[2], content[3], content[0]]
            buf =  buf.map({ kSbox[Int($0)] })
            buf[0] ^= kRcon[round]
            return Word(buf)
        }
        
        func xor (_ other: Word) -> Word {
            let value = self.value ^ other.value

            return Word(value: value)
        }
        
    }
    
}
